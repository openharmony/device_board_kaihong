// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2014 MundoReader S.L.
 * Author: Heiko Stuebner <heiko@sntech.de>
 *
 * Copyright (c) 2015 Rockchip Electronics Co. Ltd.
 * Author: Xing Zheng <zhengxing@rock-chips.com>
 */

#include <asm/div64.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/clk-provider.h>
#include <linux/iopoll.h>
#include <linux/regmap.h>
#include <linux/clk.h>
#include <linux/gcd.h>
#include <linux/clk/rockchip.h>
#include <linux/mfd/syscon.h>
#include "clk.h"

#define PLL_MODE_MASK		0x3
#define PLL_MODE_SLOW		0x0
#define PLL_MODE_NORM		0x1
#define PLL_MODE_DEEP		0x2
#define PLL_RK3328_MODE_MASK	0x1

struct rockchip_clk_pll {
	struct clk_hw		hw;

	struct clk_mux		pll_mux;
	const struct clk_ops	*pll_mux_ops;

	struct notifier_block	clk_nb;

	void __iomem		*reg_base;
	int			lock_offset;
	unsigned int		lock_shift;
	enum rockchip_pll_type	type;
	u8			flags;
	const struct rockchip_pll_rate_table *rate_table;
	unsigned int		rate_count;
	int			sel;
	unsigned long		scaling;
	spinlock_t		*lock;

	struct rockchip_clk_provider *ctx;

	bool			boost_enabled;
	u32			boost_backup_pll_usage;
	unsigned long		boost_backup_pll_rate;
	unsigned long		boost_low_rate;
	unsigned long		boost_high_rate;
	struct regmap		*boost;
#ifdef CONFIG_DEBUG_FS
	struct hlist_node	debug_node;
#endif
};

#define to_rockchip_clk_pll(_hw) container_of(_hw, struct rockchip_clk_pll, hw)
#define to_rockchip_clk_pll_nb(nb) \
			container_of(nb, struct rockchip_clk_pll, clk_nb)

static void rockchip_boost_disable_low(struct rockchip_clk_pll *pll);

#define MHZ			(1000UL * 1000UL)
#define KHZ			(1000UL)

/* CLK_PLL_TYPE_RK3066_AUTO type ops */
#define PLL_FREF_MIN		(269 * KHZ)
#define PLL_FREF_MAX		(2200 * MHZ)

#define PLL_FVCO_MIN		(440 * MHZ)
#define PLL_FVCO_MAX		(2200 * MHZ)

#define PLL_FOUT_MIN		(27500 * KHZ)
#define PLL_FOUT_MAX		(2200 * MHZ)

#define PLL_NF_MAX		(4096)
#define PLL_NR_MAX		(64)
#define PLL_NO_MAX		(16)

/* CLK_PLL_TYPE_RK3036/3366/3399_AUTO type ops */
#define MIN_FOUTVCO_FREQ	(800 * MHZ)
#define MAX_FOUTVCO_FREQ	(2000 * MHZ)

static struct rockchip_pll_rate_table auto_table;
#ifdef CONFIG_DEBUG_FS
static HLIST_HEAD(clk_boost_list);
static DEFINE_MUTEX(clk_boost_lock);
#endif

int rockchip_pll_clk_adaptive_scaling(struct clk *clk, int sel)
{
	struct clk *parent = clk_get_parent(clk);
	struct rockchip_clk_pll *pll;

	if (IS_ERR_OR_NULL(parent))
		return -EINVAL;

	pll = to_rockchip_clk_pll(__clk_get_hw(parent));
	if (!pll)
		return -EINVAL;

	pll->sel = sel;

	return 0;
}
EXPORT_SYMBOL(rockchip_pll_clk_adaptive_scaling);

int rockchip_pll_clk_rate_to_scale(struct clk *clk, unsigned long rate)
{
	const struct rockchip_pll_rate_table *rate_table;
	struct clk *parent = clk_get_parent(clk);
	struct rockchip_clk_pll *pll;
	unsigned int i;

	if (IS_ERR_OR_NULL(parent))
		return -EINVAL;

	pll = to_rockchip_clk_pll(__clk_get_hw(parent));
	if (!pll)
		return -EINVAL;

	rate_table = pll->rate_table;
	for (i = 0; i < pll->rate_count; i++) {
		if (rate >= rate_table[i].rate)
			return i;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(rockchip_pll_clk_rate_to_scale);

int rockchip_pll_clk_scale_to_rate(struct clk *clk, unsigned int scale)
{
	const struct rockchip_pll_rate_table *rate_table;
	struct clk *parent = clk_get_parent(clk);
	struct rockchip_clk_pll *pll;
	unsigned int i;

	if (IS_ERR_OR_NULL(parent))
		return -EINVAL;

	pll = to_rockchip_clk_pll(__clk_get_hw(parent));
	if (!pll)
		return -EINVAL;

	rate_table = pll->rate_table;
	for (i = 0; i < pll->rate_count; i++) {
		if (i == scale)
			return rate_table[i].rate;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(rockchip_pll_clk_scale_to_rate);

static struct rockchip_pll_rate_table *rk_pll_rate_table_get(void)
{
	return &auto_table;
}

static int rockchip_pll_clk_set_postdiv(unsigned long fout_hz,
					u32 *postdiv1,
					u32 *postdiv2,
					u32 *foutvco)
{
	unsigned long freq;

	if (fout_hz < MIN_FOUTVCO_FREQ) {
		for (*postdiv1 = 1; *postdiv1 <= 7; (*postdiv1)++) {
			for (*postdiv2 = 1; *postdiv2 <= 7; (*postdiv2)++) {
				freq = fout_hz * (*postdiv1) * (*postdiv2);
				if (freq >= MIN_FOUTVCO_FREQ &&
				    freq <= MAX_FOUTVCO_FREQ) {
					*foutvco = freq;
					return 0;
				}
			}
		}
		pr_err("CANNOT FIND postdiv1/2 to make fout in range from 800M to 2000M,fout = %lu\n",
		       fout_hz);
	} else {
		*postdiv1 = 1;
		*postdiv2 = 1;
	}
	return 0;
}

static struct rockchip_pll_rate_table *
rockchip_pll_clk_set_by_auto(struct rockchip_clk_pll *pll,
			     unsigned long fin_hz,
			     unsigned long fout_hz)
{
	struct rockchip_pll_rate_table *rate_table = rk_pll_rate_table_get();
	/* FIXME set postdiv1/2 always 1*/
	u32 foutvco = fout_hz;
	u64 fin_64, frac_64;
	u32 f_frac, postdiv1, postdiv2;
	unsigned long clk_gcd = 0;

	if (fin_hz == 0 || fout_hz == 0 || fout_hz == fin_hz)
		return NULL;

	rockchip_pll_clk_set_postdiv(fout_hz, &postdiv1, &postdiv2, &foutvco);
	rate_table->postdiv1 = postdiv1;
	rate_table->postdiv2 = postdiv2;
	rate_table->dsmpd = 1;

	if (fin_hz / MHZ * MHZ == fin_hz && fout_hz / MHZ * MHZ == fout_hz) {
		fin_hz /= MHZ;
		foutvco /= MHZ;
		clk_gcd = gcd(fin_hz, foutvco);
		rate_table->refdiv = fin_hz / clk_gcd;
		rate_table->fbdiv = foutvco / clk_gcd;

		rate_table->frac = 0;

		pr_debug("fin = %lu, fout = %lu, clk_gcd = %lu, refdiv = %u, fbdiv = %u, postdiv1 = %u, postdiv2 = %u, frac = %u\n",
			 fin_hz, fout_hz, clk_gcd, rate_table->refdiv,
			 rate_table->fbdiv, rate_table->postdiv1,
			 rate_table->postdiv2, rate_table->frac);
	} else {
		pr_debug("frac div running, fin_hz = %lu, fout_hz = %lu, fin_INT_mhz = %lu, fout_INT_mhz = %lu\n",
			 fin_hz, fout_hz,
			 fin_hz / MHZ * MHZ,
			 fout_hz / MHZ * MHZ);
		pr_debug("frac get postdiv1 = %u,  postdiv2 = %u, foutvco = %u\n",
			 rate_table->postdiv1, rate_table->postdiv2, foutvco);
		clk_gcd = gcd(fin_hz / MHZ, foutvco / MHZ);
		rate_table->refdiv = fin_hz / MHZ / clk_gcd;
		rate_table->fbdiv = foutvco / MHZ / clk_gcd;
		pr_debug("frac get refdiv = %u,  fbdiv = %u\n",
			 rate_table->refdiv, rate_table->fbdiv);

		rate_table->frac = 0;

		f_frac = (foutvco % MHZ);
		fin_64 = fin_hz;
		do_div(fin_64, (u64)rate_table->refdiv);
		frac_64 = (u64)f_frac << 24;
		do_div(frac_64, fin_64);
		rate_table->frac = (u32)frac_64;
		if (rate_table->frac > 0)
			rate_table->dsmpd = 0;
		pr_debug("frac = %x\n", rate_table->frac);
	}
	return rate_table;
}

static struct rockchip_pll_rate_table *
rockchip_rk3066_pll_clk_set_by_auto(struct rockchip_clk_pll *pll,
				    unsigned long fin_hz,
				    unsigned long fout_hz)
{
	struct rockchip_pll_rate_table *rate_table = rk_pll_rate_table_get();
	u32 nr, nf, no, nonr;
	u32 nr_out, nf_out, no_out;
	u32 n;
	u32 numerator, denominator;
	u64 fref, fvco, fout;
	unsigned long clk_gcd = 0;

	nr_out = PLL_NR_MAX + 1;
	no_out = 0;
	nf_out = 0;

	if (fin_hz == 0 || fout_hz == 0 || fout_hz == fin_hz)
		return NULL;

	clk_gcd = gcd(fin_hz, fout_hz);

	numerator = fout_hz / clk_gcd;
	denominator = fin_hz / clk_gcd;

	for (n = 1;; n++) {
		nf = numerator * n;
		nonr = denominator * n;
		if (nf > PLL_NF_MAX || nonr > (PLL_NO_MAX * PLL_NR_MAX))
			break;

		for (no = 1; no <= PLL_NO_MAX; no++) {
			if (!(no == 1 || !(no % 2)))
				continue;

			if (nonr % no)
				continue;
			nr = nonr / no;

			if (nr > PLL_NR_MAX)
				continue;

			fref = fin_hz / nr;
			if (fref < PLL_FREF_MIN || fref > PLL_FREF_MAX)
				continue;

			fvco = fref * nf;
			if (fvco < PLL_FVCO_MIN || fvco > PLL_FVCO_MAX)
				continue;

			fout = fvco / no;
			if (fout < PLL_FOUT_MIN || fout > PLL_FOUT_MAX)
				continue;

			/* select the best from all available PLL settings */
			if ((no > no_out) ||
			    ((no == no_out) && (nr < nr_out))) {
				nr_out = nr;
				nf_out = nf;
				no_out = no;
			}
		}
	}

	/* output the best PLL setting */
	if ((nr_out <= PLL_NR_MAX) && (no_out > 0)) {
		rate_table->nr = nr_out;
		rate_table->nf = nf_out;
		rate_table->no = no_out;
	} else {
		return NULL;
	}

	return rate_table;
}

static const struct rockchip_pll_rate_table *rockchip_get_pll_settings(
			    struct rockchip_clk_pll *pll, unsigned long rate)
{
	const struct rockchip_pll_rate_table  *rate_table = pll->rate_table;
	int i;

	for (i = 0; i < pll->rate_count; i++) {
		if (rate == rate_table[i].rate) {
			if (i < pll->sel) {
				pll->scaling = rate;
				return &rate_table[pll->sel];
			}
			pll->scaling = 0;
			return &rate_table[i];
		}
	}
	pll->scaling = 0;

	if (pll->type == pll_rk3066)
		return rockchip_rk3066_pll_clk_set_by_auto(pll, 24 * MHZ, rate);
	else
		return rockchip_pll_clk_set_by_auto(pll, 24 * MHZ, rate);
}

static long rockchip_pll_round_rate(struct clk_hw *hw,
			    unsigned long drate, unsigned long *prate)
{
	return drate;
}

/*
 * Wait for the pll to reach the locked state.
 * The calling set_rate function is responsible for making sure the
 * grf regmap is available.
 */
static int rockchip_pll_wait_lock(struct rockchip_clk_pll *pll)
{
	struct regmap *grf = pll->ctx->grf;
	unsigned int val;
	int ret;

	ret = regmap_read_poll_timeout(grf, pll->lock_offset, val,
				       val & BIT(pll->lock_shift), 0, 1000);
	if (ret)
		pr_err("%s: timeout waiting for pll to lock\n", __func__);

	return ret;
}

/**
 * PLL used in RK3036
 */

#define RK3036_PLLCON(i)			(i * 0x4)
#define RK3036_PLLCON0_FBDIV_MASK		0xfff
#define RK3036_PLLCON0_FBDIV_SHIFT		0
#define RK3036_PLLCON0_POSTDIV1_MASK		0x7
#define RK3036_PLLCON0_POSTDIV1_SHIFT		12
#define RK3036_PLLCON1_REFDIV_MASK		0x3f
#define RK3036_PLLCON1_REFDIV_SHIFT		0
#define RK3036_PLLCON1_POSTDIV2_MASK		0x7
#define RK3036_PLLCON1_POSTDIV2_SHIFT		6
#define RK3036_PLLCON1_LOCK_STATUS		BIT(10)
#define RK3036_PLLCON1_DSMPD_MASK		0x1
#define RK3036_PLLCON1_DSMPD_SHIFT		12
#define RK3036_PLLCON1_PWRDOWN			BIT(13)
#define RK3036_PLLCON2_FRAC_MASK		0xffffff
#define RK3036_PLLCON2_FRAC_SHIFT		0

static int rockchip_rk3036_pll_wait_lock(struct rockchip_clk_pll *pll)
{
	u32 pllcon;
	int ret;

	/*
	 * Lock time typical 250, max 500 input clock cycles @24MHz
	 * So define a very safe maximum of 1000us, meaning 24000 cycles.
	 */
	ret = readl_relaxed_poll_timeout(pll->reg_base + RK3036_PLLCON(1),
					 pllcon,
					 pllcon & RK3036_PLLCON1_LOCK_STATUS,
					 0, 1000);
	if (ret)
		pr_err("%s: timeout waiting for pll to lock\n", __func__);

	return ret;
}

static unsigned long
rockchip_rk3036_pll_con_to_rate(struct rockchip_clk_pll *pll,
				u32 con0, u32 con1)
{
	unsigned int fbdiv, postdiv1, refdiv, postdiv2;
	u64 rate64 = 24000000;

	fbdiv = ((con0 >> RK3036_PLLCON0_FBDIV_SHIFT) &
		  RK3036_PLLCON0_FBDIV_MASK);
	postdiv1 = ((con0 >> RK3036_PLLCON0_POSTDIV1_SHIFT) &
		     RK3036_PLLCON0_POSTDIV1_MASK);
	refdiv = ((con1 >> RK3036_PLLCON1_REFDIV_SHIFT) &
		   RK3036_PLLCON1_REFDIV_MASK);
	postdiv2 = ((con1 >> RK3036_PLLCON1_POSTDIV2_SHIFT) &
		     RK3036_PLLCON1_POSTDIV2_MASK);

	rate64 *= fbdiv;
	do_div(rate64, refdiv);
	do_div(rate64, postdiv1);
	do_div(rate64, postdiv2);

	return (unsigned long)rate64;
}

static void rockchip_rk3036_pll_get_params(struct rockchip_clk_pll *pll,
					struct rockchip_pll_rate_table *rate)
{
	u32 pllcon;

	pllcon = readl_relaxed(pll->reg_base + RK3036_PLLCON(0));
	rate->fbdiv = ((pllcon >> RK3036_PLLCON0_FBDIV_SHIFT)
				& RK3036_PLLCON0_FBDIV_MASK);
	rate->postdiv1 = ((pllcon >> RK3036_PLLCON0_POSTDIV1_SHIFT)
				& RK3036_PLLCON0_POSTDIV1_MASK);

	pllcon = readl_relaxed(pll->reg_base + RK3036_PLLCON(1));
	rate->refdiv = ((pllcon >> RK3036_PLLCON1_REFDIV_SHIFT)
				& RK3036_PLLCON1_REFDIV_MASK);
	rate->postdiv2 = ((pllcon >> RK3036_PLLCON1_POSTDIV2_SHIFT)
				& RK3036_PLLCON1_POSTDIV2_MASK);
	rate->dsmpd = ((pllcon >> RK3036_PLLCON1_DSMPD_SHIFT)
				& RK3036_PLLCON1_DSMPD_MASK);

	pllcon = readl_relaxed(pll->reg_base + RK3036_PLLCON(2));
	rate->frac = ((pllcon >> RK3036_PLLCON2_FRAC_SHIFT)
				& RK3036_PLLCON2_FRAC_MASK);
}

static unsigned long rockchip_rk3036_pll_recalc_rate(struct clk_hw *hw,
						     unsigned long prate)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);
	struct rockchip_pll_rate_table cur;
	u64 rate64 = prate, frac_rate64 = prate;

	if (pll->sel && pll->scaling)
		return pll->scaling;

	rockchip_rk3036_pll_get_params(pll, &cur);

	rate64 *= cur.fbdiv;
	do_div(rate64, cur.refdiv);

	if (cur.dsmpd == 0) {
		/* fractional mode */
		frac_rate64 *= cur.frac;

		do_div(frac_rate64, cur.refdiv);
		rate64 += frac_rate64 >> 24;
	}

	do_div(rate64, cur.postdiv1);
	do_div(rate64, cur.postdiv2);

	return (unsigned long)rate64;
}

static int rockchip_rk3036_pll_set_params(struct rockchip_clk_pll *pll,
				const struct rockchip_pll_rate_table *rate)
{
	const struct clk_ops *pll_mux_ops = pll->pll_mux_ops;
	struct clk_mux *pll_mux = &pll->pll_mux;
	struct rockchip_pll_rate_table cur;
	u32 pllcon;
	int rate_change_remuxed = 0;
	int cur_parent;
	int ret;

	pr_debug("%s: rate settings for %lu fbdiv: %d, postdiv1: %d, refdiv: %d, postdiv2: %d, dsmpd: %d, frac: %d\n",
		__func__, rate->rate, rate->fbdiv, rate->postdiv1, rate->refdiv,
		rate->postdiv2, rate->dsmpd, rate->frac);

	rockchip_rk3036_pll_get_params(pll, &cur);
	cur.rate = 0;

	cur_parent = pll_mux_ops->get_parent(&pll_mux->hw);
	if (cur_parent == PLL_MODE_NORM) {
		pll_mux_ops->set_parent(&pll_mux->hw, PLL_MODE_SLOW);
		rate_change_remuxed = 1;
	}

	/* update pll values */
	writel_relaxed(HIWORD_UPDATE(rate->fbdiv, RK3036_PLLCON0_FBDIV_MASK,
					  RK3036_PLLCON0_FBDIV_SHIFT) |
		       HIWORD_UPDATE(rate->postdiv1, RK3036_PLLCON0_POSTDIV1_MASK,
					     RK3036_PLLCON0_POSTDIV1_SHIFT),
		       pll->reg_base + RK3036_PLLCON(0));

	writel_relaxed(HIWORD_UPDATE(rate->refdiv, RK3036_PLLCON1_REFDIV_MASK,
						   RK3036_PLLCON1_REFDIV_SHIFT) |
		       HIWORD_UPDATE(rate->postdiv2, RK3036_PLLCON1_POSTDIV2_MASK,
						     RK3036_PLLCON1_POSTDIV2_SHIFT) |
		       HIWORD_UPDATE(rate->dsmpd, RK3036_PLLCON1_DSMPD_MASK,
						  RK3036_PLLCON1_DSMPD_SHIFT),
		       pll->reg_base + RK3036_PLLCON(1));

	/* GPLL CON2 is not HIWORD_MASK */
	pllcon = readl_relaxed(pll->reg_base + RK3036_PLLCON(2));
	pllcon &= ~(RK3036_PLLCON2_FRAC_MASK << RK3036_PLLCON2_FRAC_SHIFT);
	pllcon |= rate->frac << RK3036_PLLCON2_FRAC_SHIFT;
	writel_relaxed(pllcon, pll->reg_base + RK3036_PLLCON(2));

	rockchip_boost_disable_low(pll);

	/* wait for the pll to lock */
	ret = rockchip_rk3036_pll_wait_lock(pll);
	if (ret) {
		pr_warn("%s: pll update unsuccessful, trying to restore old params\n",
			__func__);
		rockchip_rk3036_pll_set_params(pll, &cur);
	}

	if (rate_change_remuxed)
		pll_mux_ops->set_parent(&pll_mux->hw, PLL_MODE_NORM);

	return ret;
}

static int rockchip_rk3036_pll_set_rate(struct clk_hw *hw, unsigned long drate,
					unsigned long prate)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);
	const struct rockchip_pll_rate_table *rate;

	pr_debug("%s: changing %s to %lu with a parent rate of %lu\n",
		 __func__, __clk_get_name(hw->clk), drate, prate);

	/* Get required rate settings from table */
	rate = rockchip_get_pll_settings(pll, drate);
	if (!rate) {
		pr_err("%s: Invalid rate : %lu for pll clk %s\n", __func__,
			drate, __clk_get_name(hw->clk));
		return -EINVAL;
	}

	return rockchip_rk3036_pll_set_params(pll, rate);
}

static int rockchip_rk3036_pll_enable(struct clk_hw *hw)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);

	writel(HIWORD_UPDATE(0, RK3036_PLLCON1_PWRDOWN, 0),
	       pll->reg_base + RK3036_PLLCON(1));
	rockchip_rk3036_pll_wait_lock(pll);

	return 0;
}

static void rockchip_rk3036_pll_disable(struct clk_hw *hw)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);

	writel(HIWORD_UPDATE(RK3036_PLLCON1_PWRDOWN,
			     RK3036_PLLCON1_PWRDOWN, 0),
	       pll->reg_base + RK3036_PLLCON(1));
}

static int rockchip_rk3036_pll_is_enabled(struct clk_hw *hw)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);
	u32 pllcon = readl(pll->reg_base + RK3036_PLLCON(1));

	return !(pllcon & RK3036_PLLCON1_PWRDOWN);
}

static int rockchip_rk3036_pll_init(struct clk_hw *hw)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);
	const struct rockchip_pll_rate_table *rate;
	struct rockchip_pll_rate_table cur;
	unsigned long drate;

	if (!(pll->flags & ROCKCHIP_PLL_SYNC_RATE))
		return 0;

	drate = clk_hw_get_rate(hw);
	rate = rockchip_get_pll_settings(pll, drate);

	/* when no rate setting for the current rate, rely on clk_set_rate */
	if (!rate)
		return 0;

	rockchip_rk3036_pll_get_params(pll, &cur);

	pr_debug("%s: pll %s@%lu: Hz\n", __func__, __clk_get_name(hw->clk),
		 drate);
	pr_debug("old - fbdiv: %d, postdiv1: %d, refdiv: %d, postdiv2: %d, dsmpd: %d, frac: %d\n",
		 cur.fbdiv, cur.postdiv1, cur.refdiv, cur.postdiv2,
		 cur.dsmpd, cur.frac);
	pr_debug("new - fbdiv: %d, postdiv1: %d, refdiv: %d, postdiv2: %d, dsmpd: %d, frac: %d\n",
		 rate->fbdiv, rate->postdiv1, rate->refdiv, rate->postdiv2,
		 rate->dsmpd, rate->frac);

	if (rate->fbdiv != cur.fbdiv || rate->postdiv1 != cur.postdiv1 ||
		rate->refdiv != cur.refdiv || rate->postdiv2 != cur.postdiv2 ||
		rate->dsmpd != cur.dsmpd ||
		(!cur.dsmpd && (rate->frac != cur.frac))) {
		struct clk *parent = clk_get_parent(hw->clk);

		if (!parent) {
			pr_warn("%s: parent of %s not available\n",
				__func__, __clk_get_name(hw->clk));
			return 0;
		}

		pr_debug("%s: pll %s: rate params do not match rate table, adjusting\n",
			 __func__, __clk_get_name(hw->clk));
		rockchip_rk3036_pll_set_params(pll, rate);
	}

	return 0;
}

static const struct clk_ops rockchip_rk3036_pll_clk_norate_ops = {
	.recalc_rate = rockchip_rk3036_pll_recalc_rate,
	.enable = rockchip_rk3036_pll_enable,
	.disable = rockchip_rk3036_pll_disable,
	.is_enabled = rockchip_rk3036_pll_is_enabled,
};

static const struct clk_ops rockchip_rk3036_pll_clk_ops = {
	.recalc_rate = rockchip_rk3036_pll_recalc_rate,
	.round_rate = rockchip_pll_round_rate,
	.set_rate = rockchip_rk3036_pll_set_rate,
	.enable = rockchip_rk3036_pll_enable,
	.disable = rockchip_rk3036_pll_disable,
	.is_enabled = rockchip_rk3036_pll_is_enabled,
	.init = rockchip_rk3036_pll_init,
};

/**
 * PLL used in RK3066, RK3188 and RK3288
 */

#define RK3066_PLL_RESET_DELAY(nr)	((nr * 500) / 24 + 1)

#define RK3066_PLLCON(i)		(i * 0x4)
#define RK3066_PLLCON0_OD_MASK		0xf
#define RK3066_PLLCON0_OD_SHIFT		0
#define RK3066_PLLCON0_NR_MASK		0x3f
#define RK3066_PLLCON0_NR_SHIFT		8
#define RK3066_PLLCON1_NF_MASK		0x1fff
#define RK3066_PLLCON1_NF_SHIFT		0
#define RK3066_PLLCON2_NB_MASK		0xfff
#define RK3066_PLLCON2_NB_SHIFT		0
#define RK3066_PLLCON3_RESET		(1 << 5)
#define RK3066_PLLCON3_PWRDOWN		(1 << 1)
#define RK3066_PLLCON3_BYPASS		(1 << 0)

static void rockchip_rk3066_pll_get_params(struct rockchip_clk_pll *pll,
					struct rockchip_pll_rate_table *rate)
{
	u32 pllcon;

	pllcon = readl_relaxed(pll->reg_base + RK3066_PLLCON(0));
	rate->nr = ((pllcon >> RK3066_PLLCON0_NR_SHIFT)
				& RK3066_PLLCON0_NR_MASK) + 1;
	rate->no = ((pllcon >> RK3066_PLLCON0_OD_SHIFT)
				& RK3066_PLLCON0_OD_MASK) + 1;

	pllcon = readl_relaxed(pll->reg_base + RK3066_PLLCON(1));
	rate->nf = ((pllcon >> RK3066_PLLCON1_NF_SHIFT)
				& RK3066_PLLCON1_NF_MASK) + 1;

	pllcon = readl_relaxed(pll->reg_base + RK3066_PLLCON(2));
	rate->nb = ((pllcon >> RK3066_PLLCON2_NB_SHIFT)
				& RK3066_PLLCON2_NB_MASK) + 1;
}

static unsigned long rockchip_rk3066_pll_recalc_rate(struct clk_hw *hw,
						     unsigned long prate)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);
	struct rockchip_pll_rate_table cur;
	u64 rate64 = prate;
	u32 pllcon;

	pllcon = readl_relaxed(pll->reg_base + RK3066_PLLCON(3));
	if (pllcon & RK3066_PLLCON3_BYPASS) {
		pr_debug("%s: pll %s is bypassed\n", __func__,
			clk_hw_get_name(hw));
		return prate;
	}

	if (pll->sel && pll->scaling)
		return pll->scaling;

	rockchip_rk3066_pll_get_params(pll, &cur);

	rate64 *= cur.nf;
	do_div(rate64, cur.nr);
	do_div(rate64, cur.no);

	return (unsigned long)rate64;
}

static int rockchip_rk3066_pll_set_params(struct rockchip_clk_pll *pll,
				const struct rockchip_pll_rate_table *rate)
{
	const struct clk_ops *pll_mux_ops = pll->pll_mux_ops;
	struct clk_mux *pll_mux = &pll->pll_mux;
	struct rockchip_pll_rate_table cur;
	int rate_change_remuxed = 0;
	int cur_parent;
	int ret;

	pr_debug("%s: rate settings for %lu (nr, no, nf): (%d, %d, %d)\n",
		 __func__, rate->rate, rate->nr, rate->no, rate->nf);

	rockchip_rk3066_pll_get_params(pll, &cur);
	cur.rate = 0;

	cur_parent = pll_mux_ops->get_parent(&pll_mux->hw);
	if (cur_parent == PLL_MODE_NORM) {
		pll_mux_ops->set_parent(&pll_mux->hw, PLL_MODE_SLOW);
		rate_change_remuxed = 1;
	}

	/* enter reset mode */
	writel(HIWORD_UPDATE(RK3066_PLLCON3_RESET, RK3066_PLLCON3_RESET, 0),
	       pll->reg_base + RK3066_PLLCON(3));

	/* update pll values */
	writel(HIWORD_UPDATE(rate->nr - 1, RK3066_PLLCON0_NR_MASK,
					   RK3066_PLLCON0_NR_SHIFT) |
	       HIWORD_UPDATE(rate->no - 1, RK3066_PLLCON0_OD_MASK,
					   RK3066_PLLCON0_OD_SHIFT),
	       pll->reg_base + RK3066_PLLCON(0));

	writel_relaxed(HIWORD_UPDATE(rate->nf - 1, RK3066_PLLCON1_NF_MASK,
						   RK3066_PLLCON1_NF_SHIFT),
		       pll->reg_base + RK3066_PLLCON(1));
	writel_relaxed(HIWORD_UPDATE(rate->nb - 1, RK3066_PLLCON2_NB_MASK,
						   RK3066_PLLCON2_NB_SHIFT),
		       pll->reg_base + RK3066_PLLCON(2));

	/* leave reset and wait the reset_delay */
	writel(HIWORD_UPDATE(0, RK3066_PLLCON3_RESET, 0),
	       pll->reg_base + RK3066_PLLCON(3));
	udelay(RK3066_PLL_RESET_DELAY(rate->nr));

	/* wait for the pll to lock */
	ret = rockchip_pll_wait_lock(pll);
	if (ret) {
		pr_warn("%s: pll update unsuccessful, trying to restore old params\n",
			__func__);
		rockchip_rk3066_pll_set_params(pll, &cur);
	}

	if (rate_change_remuxed)
		pll_mux_ops->set_parent(&pll_mux->hw, PLL_MODE_NORM);

	return ret;
}

static int rockchip_rk3066_pll_set_rate(struct clk_hw *hw, unsigned long drate,
					unsigned long prate)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);
	const struct rockchip_pll_rate_table *rate;
	unsigned long old_rate = rockchip_rk3066_pll_recalc_rate(hw, prate);
	struct regmap *grf = pll->ctx->grf;
	int ret;

	if (IS_ERR(grf)) {
		pr_debug("%s: grf regmap not available, aborting rate change\n",
			 __func__);
		return PTR_ERR(grf);
	}

	pr_debug("%s: changing %s from %lu to %lu with a parent rate of %lu\n",
		 __func__, clk_hw_get_name(hw), old_rate, drate, prate);

	/* Get required rate settings from table */
	rate = rockchip_get_pll_settings(pll, drate);
	if (!rate) {
		pr_err("%s: Invalid rate : %lu for pll clk %s\n", __func__,
			drate, clk_hw_get_name(hw));
		return -EINVAL;
	}

	ret = rockchip_rk3066_pll_set_params(pll, rate);
	if (ret)
		pll->scaling = 0;

	return ret;
}

static int rockchip_rk3066_pll_enable(struct clk_hw *hw)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);

	writel(HIWORD_UPDATE(0, RK3066_PLLCON3_PWRDOWN, 0),
	       pll->reg_base + RK3066_PLLCON(3));
	rockchip_pll_wait_lock(pll);

	return 0;
}

static void rockchip_rk3066_pll_disable(struct clk_hw *hw)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);

	writel(HIWORD_UPDATE(RK3066_PLLCON3_PWRDOWN,
			     RK3066_PLLCON3_PWRDOWN, 0),
	       pll->reg_base + RK3066_PLLCON(3));
}

static int rockchip_rk3066_pll_is_enabled(struct clk_hw *hw)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);
	u32 pllcon = readl(pll->reg_base + RK3066_PLLCON(3));

	return !(pllcon & RK3066_PLLCON3_PWRDOWN);
}

static int rockchip_rk3066_pll_init(struct clk_hw *hw)
{
	struct rockchip_clk_pll *pll = to_rockchip_clk_pll(hw);
	const struct rockchip_pll_rate_table *rate;
	struct rockchip_pll_rate_table cur;
	unsigned long drate;

	if (!(pll->flags & ROCKCHIP_PLL_SYNC_RATE))
		return 0;

	drate = clk_hw_get_rate(hw);
	rate = rockchip_get_pll_settings(pll, drate);

	/* when no rate setting for the current rate, rely on clk_set_rate */
	if (!rate)
		return 0;

	rockchip_rk3066_pll_get_params(pll, &cur);

	pr_debug("%s: pll %s@%lu: nr (%d:%d); no (%d:%d); nf(%d:%d), nb(%d:%d)\n",
		 __func__, clk_hw_get_name(hw), drate, rate->nr, cur.nr,
		 rate->no, cur.no, rate->nf, cur.nf, rate->nb, cur.nb);
	if (rate->nr != cur.nr || rate->no != cur.no || rate->nf != cur.nf
						     || rate->nb != cur.nb) {
		pr_debug("%s: pll %s: rate params do not match rate table, adjusting\n",
			 __func__, clk_hw_get_name(hw));
		rockchip_rk3066_pll_set_params(pll, rate);
	}

	return 0;
}

static const struct clk_ops rockchip_rk3066_pll_clk_norate_ops = {
	.recalc_rate = rockchip_rk3066_pll_recalc_rate,
	.enable = rockchip_rk3066_pll_enable,
	.disable = rockchip_rk3066_pll_disable,
	.is_enabled = rockchip_rk3066_pll_is_enabled,
};

static const struct clk_ops rockchip_rk3066_pll_clk_ops = {
	.recalc_rate = rockchip_rk3066_pll_recalc_rate,
	.round_rate = rockchip_pll_round_rate,
	.set_rate = rockchip_rk3066_pll_set_rate,
	.enable = rockchip_rk3066_pll_enable,
	.disable = rockchip_rk3066_pll_disable,
	.is_enabled = rockchip_rk3066_pll_is_enabled,
	.init = rockchip_rk3066_pll_init,
};

/**
 * PLL used in RK3399
 */

