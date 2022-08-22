/*
 * Copyright (C) 2014 Red Hat
 * Copyright (C) 2014 Intel Corp.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 * Rob Clark <robdclark@gmail.com>
 * Daniel Vetter <daniel.vetter@ffwll.ch>
 */

#include <linux/dma-fence.h>
#include <linux/ktime.h>

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_atomic_uapi.h>
#include <drm/drm_bridge.h>
#include <drm/drm_damage_helper.h>
#include <drm/drm_device.h>
#include <drm/drm_drv.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_print.h>
#include <drm/drm_self_refresh_helper.h>
#include <drm/drm_vblank.h>
#include <drm/drm_writeback.h>

#include "drm_crtc_helper_internal.h"
#include "drm_crtc_internal.h"

/**
 * DOC: overview
 *
 * This helper library provides implementations of check and commit functions on
 * top of the CRTC modeset helper callbacks and the plane helper callbacks. It
 * also provides convenience implementations for the atomic state handling
 * callbacks for drivers which don't need to subclass the drm core structures to
 * add their own additional internal state.
 *
 * This library also provides default implementations for the check callback in
 * drm_atomic_helper_check() and for the commit callback with
 * drm_atomic_helper_commit(). But the individual stages and callbacks are
 * exposed to allow drivers to mix and match and e.g. use the plane helpers only
 * together with a driver private modeset implementation.
 *
 * This library also provides implementations for all the legacy driver
 * interfaces on top of the atomic interface. See drm_atomic_helper_set_config(),
 * drm_atomic_helper_disable_plane(), drm_atomic_helper_disable_plane() and the
 * various functions to implement set_property callbacks. New drivers must not
 * implement these functions themselves but must use the provided helpers.
 *
 * The atomic helper uses the same function table structures as all other
 * modesetting helpers. See the documentation for &struct drm_crtc_helper_funcs,
 * struct &drm_encoder_helper_funcs and &struct drm_connector_helper_funcs. It
 * also shares the &struct drm_plane_helper_funcs function table with the plane
 * helpers.
 */
static void
drm_atomic_helper_plane_changed(struct drm_atomic_state *state,
				struct drm_plane_state *old_plane_state,
				struct drm_plane_state *plane_state,
				struct drm_plane *plane)
{
	struct drm_crtc_state *crtc_state;

	if (old_plane_state->crtc) {
		crtc_state = drm_atomic_get_new_crtc_state(state,
							   old_plane_state->crtc);

		if (WARN_ON(!crtc_state))
			return;

		crtc_state->planes_changed = true;
	}

	if (plane_state->crtc) {
		crtc_state = drm_atomic_get_new_crtc_state(state, plane_state->crtc);

		if (WARN_ON(!crtc_state))
			return;

		crtc_state->planes_changed = true;
	}
}

static int handle_conflicting_encoders(struct drm_atomic_state *state,
				       bool disable_conflicting_encoders)
{
	struct drm_connector_state *new_conn_state;
	struct drm_connector *connector;
	struct drm_connector_list_iter conn_iter;
	struct drm_encoder *encoder;
	unsigned encoder_mask = 0;
	int i, ret = 0;

	/*
	 * First loop, find all newly assigned encoders from the connectors
	 * part of the state. If the same encoder is assigned to multiple
	 * connectors bail out.
	 */
	for_each_new_connector_in_state(state, connector, new_conn_state, i) {
		const struct drm_connector_helper_funcs *funcs = connector->helper_private;
		struct drm_encoder *new_encoder;

		if (!new_conn_state->crtc)
			continue;

		if (funcs->atomic_best_encoder)
			new_encoder = funcs->atomic_best_encoder(connector, new_conn_state);
		else if (funcs->best_encoder)
			new_encoder = funcs->best_encoder(connector);
		else
			new_encoder = drm_connector_get_single_encoder(connector);

		if (new_encoder) {
			if (encoder_mask & drm_encoder_mask(new_encoder)) {
				DRM_DEBUG_ATOMIC("[ENCODER:%d:%s] on [CONNECTOR:%d:%s] already assigned\n",
					new_encoder->base.id, new_encoder->name,
					connector->base.id, connector->name);

				return -EINVAL;
			}

			encoder_mask |= drm_encoder_mask(new_encoder);
		}
	}

	if (!encoder_mask)
		return 0;

	/*
	 * Second loop, iterate over all connectors not part of the state.
	 *
	 * If a conflicting encoder is found and disable_conflicting_encoders
	 * is not set, an error is returned. Userspace can provide a solution
	 * through the atomic ioctl.
	 *
	 * If the flag is set conflicting connectors are removed from the CRTC
	 * and the CRTC is disabled if no encoder is left. This preserves
	 * compatibility with the legacy set_config behavior.
	 */
	drm_connector_list_iter_begin(state->dev, &conn_iter);
	drm_for_each_connector_iter(connector, &conn_iter) {
		struct drm_crtc_state *crtc_state;

		if (drm_atomic_get_new_connector_state(state, connector))
			continue;

		encoder = connector->state->best_encoder;
		if (!encoder || !(encoder_mask & drm_encoder_mask(encoder)))
			continue;

		if (!disable_conflicting_encoders) {
			DRM_DEBUG_ATOMIC("[ENCODER:%d:%s] in use on [CRTC:%d:%s] by [CONNECTOR:%d:%s]\n",
					 encoder->base.id, encoder->name,
					 connector->state->crtc->base.id,
					 connector->state->crtc->name,
					 connector->base.id, connector->name);
			ret = -EINVAL;
			goto out;
		}

		new_conn_state = drm_atomic_get_connector_state(state, connector);
		if (IS_ERR(new_conn_state)) {
			ret = PTR_ERR(new_conn_state);
			goto out;
		}

		DRM_DEBUG_ATOMIC("[ENCODER:%d:%s] in use on [CRTC:%d:%s], disabling [CONNECTOR:%d:%s]\n",
				 encoder->base.id, encoder->name,
				 new_conn_state->crtc->base.id, new_conn_state->crtc->name,
				 connector->base.id, connector->name);

		crtc_state = drm_atomic_get_new_crtc_state(state, new_conn_state->crtc);

		ret = drm_atomic_set_crtc_for_connector(new_conn_state, NULL);
		if (ret)
			goto out;

		if (!crtc_state->connector_mask) {
			ret = drm_atomic_set_mode_prop_for_crtc(crtc_state,
								NULL);
			if (ret < 0)
				goto out;

			crtc_state->active = false;
		}
	}
out:
	drm_connector_list_iter_end(&conn_iter);

	return ret;
}

static void
set_best_encoder(struct drm_atomic_state *state,
		 struct drm_connector_state *conn_state,
		 struct drm_encoder *encoder)
{
	struct drm_crtc_state *crtc_state;
	struct drm_crtc *crtc;

	if (conn_state->best_encoder) {
		/* Unset the encoder_mask in the old crtc state. */
		crtc = conn_state->connector->state->crtc;

		/* A NULL crtc is an error here because we should have
		 * duplicated a NULL best_encoder when crtc was NULL.
		 * As an exception restoring duplicated atomic state
		 * during resume is allowed, so don't warn when
		 * best_encoder is equal to encoder we intend to set.
		 */
		WARN_ON(!crtc && encoder != conn_state->best_encoder);
		if (crtc) {
			crtc_state = drm_atomic_get_new_crtc_state(state, crtc);

			crtc_state->encoder_mask &=
				~drm_encoder_mask(conn_state->best_encoder);
		}
	}

	if (encoder) {
		crtc = conn_state->crtc;
		WARN_ON(!crtc);
		if (crtc) {
			crtc_state = drm_atomic_get_new_crtc_state(state, crtc);

			crtc_state->encoder_mask |=
				drm_encoder_mask(encoder);
		}
	}

	conn_state->best_encoder = encoder;
}

static void
steal_encoder(struct drm_atomic_state *state,
	      struct drm_encoder *encoder)
{
	struct drm_crtc_state *crtc_state;
	struct drm_connector *connector;
	struct drm_connector_state *old_connector_state, *new_connector_state;
	int i;

	for_each_oldnew_connector_in_state(state, connector, old_connector_state, new_connector_state, i) {
		struct drm_crtc *encoder_crtc;

		if (new_connector_state->best_encoder != encoder)
			continue;

		encoder_crtc = old_connector_state->crtc;

		DRM_DEBUG_ATOMIC("[ENCODER:%d:%s] in use on [CRTC:%d:%s], stealing it\n",
				 encoder->base.id, encoder->name,
				 encoder_crtc->base.id, encoder_crtc->name);

		set_best_encoder(state, new_connector_state, NULL);

		crtc_state = drm_atomic_get_new_crtc_state(state, encoder_crtc);
		crtc_state->connectors_changed = true;

		return;
	}
}

static int
update_connector_routing(struct drm_atomic_state *state,
			 struct drm_connector *connector,
			 struct drm_connector_state *old_connector_state,
			 struct drm_connector_state *new_connector_state)
{
	const struct drm_connector_helper_funcs *funcs;
	struct drm_encoder *new_encoder;
	struct drm_crtc_state *crtc_state;

	DRM_DEBUG_ATOMIC("Updating routing for [CONNECTOR:%d:%s]\n",
			 connector->base.id,
			 connector->name);

	if (old_connector_state->crtc != new_connector_state->crtc) {
		if (old_connector_state->crtc) {
			crtc_state = drm_atomic_get_new_crtc_state(state, old_connector_state->crtc);
			if (connector->connector_type != DRM_MODE_CONNECTOR_WRITEBACK)
				crtc_state->connectors_changed = true;
		}

		if (new_connector_state->crtc) {
			crtc_state = drm_atomic_get_new_crtc_state(state, new_connector_state->crtc);
			if (connector->connector_type != DRM_MODE_CONNECTOR_WRITEBACK)
				crtc_state->connectors_changed = true;
		}
	}

	if (!new_connector_state->crtc) {
		DRM_DEBUG_ATOMIC("Disabling [CONNECTOR:%d:%s]\n",
				connector->base.id,
				connector->name);

		set_best_encoder(state, new_connector_state, NULL);

		return 0;
	}

	crtc_state = drm_atomic_get_new_crtc_state(state,
						   new_connector_state->crtc);
	/*
	 * For compatibility with legacy users, we want to make sure that
	 * we allow DPMS On->Off modesets on unregistered connectors. Modesets
	 * which would result in anything else must be considered invalid, to
	 * avoid turning on new displays on dead connectors.
	 *
	 * Since the connector can be unregistered at any point during an
	 * atomic check or commit, this is racy. But that's OK: all we care
	 * about is ensuring that userspace can't do anything but shut off the
	 * display on a connector that was destroyed after it's been notified,
	 * not before.
	 *
	 * Additionally, we also want to ignore connector registration when
	 * we're trying to restore an atomic state during system resume since
	 * there's a chance the connector may have been destroyed during the
	 * process, but it's better to ignore that then cause
	 * drm_atomic_helper_resume() to fail.
	 */
	if (!state->duplicated && drm_connector_is_unregistered(connector) &&
	    crtc_state->active) {
		DRM_DEBUG_ATOMIC("[CONNECTOR:%d:%s] is not registered\n",
				 connector->base.id, connector->name);
		return -EINVAL;
	}

	funcs = connector->helper_private;

	if (funcs->atomic_best_encoder)
		new_encoder = funcs->atomic_best_encoder(connector,
							 new_connector_state);
	else if (funcs->best_encoder)
		new_encoder = funcs->best_encoder(connector);
	else
		new_encoder = drm_connector_get_single_encoder(connector);

	if (!new_encoder) {
		DRM_DEBUG_ATOMIC("No suitable encoder found for [CONNECTOR:%d:%s]\n",
				 connector->base.id,
				 connector->name);
		return -EINVAL;
	}

	if (!drm_encoder_crtc_ok(new_encoder, new_connector_state->crtc)) {
		DRM_DEBUG_ATOMIC("[ENCODER:%d:%s] incompatible with [CRTC:%d:%s]\n",
				 new_encoder->base.id,
				 new_encoder->name,
				 new_connector_state->crtc->base.id,
				 new_connector_state->crtc->name);
		return -EINVAL;
	}

	if (new_encoder == new_connector_state->best_encoder) {
		set_best_encoder(state, new_connector_state, new_encoder);

		DRM_DEBUG_ATOMIC("[CONNECTOR:%d:%s] keeps [ENCODER:%d:%s], now on [CRTC:%d:%s]\n",
				 connector->base.id,
				 connector->name,
				 new_encoder->base.id,
				 new_encoder->name,
				 new_connector_state->crtc->base.id,
				 new_connector_state->crtc->name);

		return 0;
	}

	steal_encoder(state, new_encoder);

	set_best_encoder(state, new_connector_state, new_encoder);

	if (connector->connector_type != DRM_MODE_CONNECTOR_WRITEBACK)
		crtc_state->connectors_changed = true;

	DRM_DEBUG_ATOMIC("[CONNECTOR:%d:%s] using [ENCODER:%d:%s] on [CRTC:%d:%s]\n",
			 connector->base.id,
			 connector->name,
			 new_encoder->base.id,
			 new_encoder->name,
			 new_connector_state->crtc->base.id,
			 new_connector_state->crtc->name);

	return 0;
}

static int
mode_fixup(struct drm_atomic_state *state)
{
	struct drm_crtc *crtc;
	struct drm_crtc_state *new_crtc_state;
	struct drm_connector *connector;
	struct drm_connector_state *new_conn_state;
	int i;
	int ret;

	for_each_new_crtc_in_state(state, crtc, new_crtc_state, i) {
		if (!new_crtc_state->mode_changed &&
		    !new_crtc_state->connectors_changed)
			continue;

		drm_mode_copy(&new_crtc_state->adjusted_mode, &new_crtc_state->mode);
	}

	for_each_new_connector_in_state(state, connector, new_conn_state, i) {
		const struct drm_encoder_helper_funcs *funcs;
		struct drm_encoder *encoder;
		struct drm_bridge *bridge;

		WARN_ON(!!new_conn_state->best_encoder != !!new_conn_state->crtc);

		if (!new_conn_state->crtc || !new_conn_state->best_encoder)
			continue;

		new_crtc_state =
			drm_atomic_get_new_crtc_state(state, new_conn_state->crtc);

		/*
		 * Each encoder has at most one connector (since we always steal
		 * it away), so we won't call ->mode_fixup twice.
		 */
		encoder = new_conn_state->best_encoder;
		funcs = encoder->helper_private;

		bridge = drm_bridge_chain_get_first_bridge(encoder);
		ret = drm_atomic_bridge_chain_check(bridge,
						    new_crtc_state,
						    new_conn_state);
		if (ret) {
			DRM_DEBUG_ATOMIC("Bridge atomic check failed\n");
			return ret;
		}

		if (funcs && funcs->atomic_check) {
			ret = funcs->atomic_check(encoder, new_crtc_state,
						  new_conn_state);
			if (ret) {
				DRM_DEBUG_ATOMIC("[ENCODER:%d:%s] check failed\n",
						 encoder->base.id, encoder->name);
				return ret;
			}
		} else if (funcs && funcs->mode_fixup) {
			ret = funcs->mode_fixup(encoder, &new_crtc_state->mode,
						&new_crtc_state->adjusted_mode);
			if (!ret) {
				DRM_DEBUG_ATOMIC("[ENCODER:%d:%s] fixup failed\n",
						 encoder->base.id, encoder->name);
				return -EINVAL;
			}
		}
	}

	for_each_new_crtc_in_state(state, crtc, new_crtc_state, i) {
		const struct drm_crtc_helper_funcs *funcs;

		if (!new_crtc_state->enable)
			continue;

		if (!new_crtc_state->mode_changed &&
		    !new_crtc_state->connectors_changed)
			continue;

		funcs = crtc->helper_private;
		if (!funcs || !funcs->mode_fixup)
			continue;

		ret = funcs->mode_fixup(crtc, &new_crtc_state->mode,
					&new_crtc_state->adjusted_mode);
		if (!ret) {
			DRM_DEBUG_ATOMIC("[CRTC:%d:%s] fixup failed\n",
					 crtc->base.id, crtc->name);
			return -EINVAL;
		}
	}

	return 0;
}

static enum drm_mode_status mode_valid_path(struct drm_connector *connector,
					    struct drm_encoder *encoder,
					    struct drm_crtc *crtc,
					    const struct drm_display_mode *mode)
{
	struct drm_bridge *bridge;
	enum drm_mode_status ret;

	ret = drm_encoder_mode_valid(encoder, mode);
	if (ret != MODE_OK) {
		DRM_DEBUG_ATOMIC("[ENCODER:%d:%s] mode_valid() failed\n",
				encoder->base.id, encoder->name);
		return ret;
	}

	bridge = drm_bridge_chain_get_first_bridge(encoder);
	ret = drm_bridge_chain_mode_valid(bridge, &connector->display_info,
					  mode);
	if (ret != MODE_OK) {
		DRM_DEBUG_ATOMIC("[BRIDGE] mode_valid() failed\n");
		return ret;
	}

	ret = drm_crtc_mode_valid(crtc, mode);
	if (ret != MODE_OK) {
		DRM_DEBUG_ATOMIC("[CRTC:%d:%s] mode_valid() failed\n",
				crtc->base.id, crtc->name);
		return ret;
	}

	return ret;
}

static int
mode_valid(struct drm_atomic_state *state)
{
	struct drm_connector_state *conn_state;
	struct drm_connector *connector;
	int i;

	for_each_new_connector_in_state(state, connector, conn_state, i) {
		struct drm_encoder *encoder = conn_state->best_encoder;
		struct drm_crtc *crtc = conn_state->crtc;
		struct drm_crtc_state *crtc_state;
		enum drm_mode_status mode_status;
		const struct drm_display_mode *mode;

		if (!crtc || !encoder)
			continue;

		crtc_state = drm_atomic_get_new_crtc_state(state, crtc);
		if (!crtc_state)
			continue;
		if (!crtc_state->mode_changed && !crtc_state->connectors_changed)
			continue;

		mode = &crtc_state->mode;

		mode_status = mode_valid_path(connector, encoder, crtc, mode);
		if (mode_status != MODE_OK)
			return -EINVAL;
	}

	return 0;
}

/**
 * drm_atomic_helper_check_modeset - validate state object for modeset changes
 * @dev: DRM device
 * @state: the driver state object
 *
 * Check the state object to see if the requested state is physically possible.
 * This does all the CRTC and connector related computations for an atomic
 * update and adds any additional connectors needed for full modesets. It calls
 * the various per-object callbacks in the follow order:
 *
 * 1. &drm_connector_helper_funcs.atomic_best_encoder for determining the new encoder.
 * 2. &drm_connector_helper_funcs.atomic_check to validate the connector state.
 * 3. If it's determined a modeset is needed then all connectors on the affected
 *    CRTC are added and &drm_connector_helper_funcs.atomic_check is run on them.
 * 4. &drm_encoder_helper_funcs.mode_valid, &drm_bridge_funcs.mode_valid and
 *    &drm_crtc_helper_funcs.mode_valid are called on the affected components.
 * 5. &drm_bridge_funcs.mode_fixup is called on all encoder bridges.
 * 6. &drm_encoder_helper_funcs.atomic_check is called to validate any encoder state.
 *    This function is only called when the encoder will be part of a configured CRTC,
 *    it must not be used for implementing connector property validation.
 *    If this function is NULL, &drm_atomic_encoder_helper_funcs.mode_fixup is called
 *    instead.
 * 7. &drm_crtc_helper_funcs.mode_fixup is called last, to fix up the mode with CRTC constraints.
 *
 * &drm_crtc_state.mode_changed is set when the input mode is changed.
 * &drm_crtc_state.connectors_changed is set when a connector is added or
 * removed from the CRTC.  &drm_crtc_state.active_changed is set when
 * &drm_crtc_state.active changes, which is used for DPMS.
 * &drm_crtc_state.no_vblank is set from the result of drm_dev_has_vblank().
 * See also: drm_atomic_crtc_needs_modeset()
 *
 * IMPORTANT:
 *
 * Drivers which set &drm_crtc_state.mode_changed (e.g. in their
 * &drm_plane_helper_funcs.atomic_check hooks if a plane update can't be done
 * without a full modeset) _must_ call this function afterwards after that
 * change. It is permitted to call this function multiple times for the same
 * update, e.g. when the &drm_crtc_helper_funcs.atomic_check functions depend
 * upon the adjusted dotclock for fifo space allocation and watermark
 * computation.
 *
 * RETURNS:
 * Zero for success or -errno
 */
int
drm_atomic_helper_check_modeset(struct drm_device *dev,
				struct drm_atomic_state *state)
{
	struct drm_crtc *crtc;
	struct drm_crtc_state *old_crtc_state, *new_crtc_state;
	struct drm_connector *connector;
	struct drm_connector_state *old_connector_state, *new_connector_state;
	int i, ret;
	unsigned connectors_mask = 0;

	for_each_oldnew_crtc_in_state(state, crtc, old_crtc_state, new_crtc_state, i) {
		bool has_connectors =
			!!new_crtc_state->connector_mask;

		WARN_ON(!drm_modeset_is_locked(&crtc->mutex));

		if (!drm_mode_equal(&old_crtc_state->mode, &new_crtc_state->mode)) {
			DRM_DEBUG_ATOMIC("[CRTC:%d:%s] mode changed\n",
					 crtc->base.id, crtc->name);
			new_crtc_state->mode_changed = true;
		}

		if (old_crtc_state->enable != new_crtc_state->enable) {
			DRM_DEBUG_ATOMIC("[CRTC:%d:%s] enable changed\n",
					 crtc->base.id, crtc->name);

			/*
			 * For clarity this assignment is done here, but
			 * enable == 0 is only true when there are no
			 * connectors and a NULL mode.
			 *
			 * The other way around is true as well. enable != 0
			 * iff connectors are attached and a mode is set.
			 */
			new_crtc_state->mode_changed = true;
			new_crtc_state->connectors_changed = true;
		}

		if (old_crtc_state->active != new_crtc_state->active) {
			DRM_DEBUG_ATOMIC("[CRTC:%d:%s] active changed\n",
					 crtc->base.id, crtc->name);
			new_crtc_state->active_changed = true;
		}

		if (new_crtc_state->enable != has_connectors) {
			DRM_DEBUG_ATOMIC("[CRTC:%d:%s] enabled/connectors mismatch\n",
					 crtc->base.id, crtc->name);

			return -EINVAL;
		}

		if (drm_dev_has_vblank(dev))
			new_crtc_state->no_vblank = false;
		else
			new_crtc_state->no_vblank = true;
	}

	ret = handle_conflicting_encoders(state, false);
	if (ret)
		return ret;

	for_each_oldnew_connector_in_state(state, connector, old_connector_state, new_connector_state, i) {
		const struct drm_connector_helper_funcs *funcs = connector->helper_private;

		WARN_ON(!drm_modeset_is_locked(&dev->mode_config.connection_mutex));

		/*
		 * This only sets crtc->connectors_changed for routing changes,
		 * drivers must set crtc->connectors_changed themselves when
		 * connector properties need to be updated.
		 */
		ret = update_connector_routing(state, connector,
					       old_connector_state,
					       new_connector_state);
		if (ret)
			return ret;
		if (old_connector_state->crtc) {
			new_crtc_state = drm_atomic_get_new_crtc_state(state,
								       old_connector_state->crtc);
			if (old_connector_state->link_status !=
			    new_connector_state->link_status)
				new_crtc_state->connectors_changed = true;

			if (old_connector_state->max_requested_bpc !=
			    new_connector_state->max_requested_bpc)
				new_crtc_state->connectors_changed = true;
		}

		if (funcs->atomic_check)
			ret = funcs->atomic_check(connector, state);
		if (ret)
			return ret;

		connectors_mask |= BIT(i);
	}

	/*
	 * After all the routing has been prepared we need to add in any
	 * connector which is itself unchanged, but whose CRTC changes its
	 * configuration. This must be done before calling mode_fixup in case a
	 * crtc only changed its mode but has the same set of connectors.
	 */
	for_each_oldnew_crtc_in_state(state, crtc, old_crtc_state, new_crtc_state, i) {
		if (!drm_atomic_crtc_needs_modeset(new_crtc_state))
			continue;

		DRM_DEBUG_ATOMIC("[CRTC:%d:%s] needs all connectors, enable: %c, active: %c\n",
				 crtc->base.id, crtc->name,
				 new_crtc_state->enable ? 'y' : 'n',
				 new_crtc_state->active ? 'y' : 'n');

		ret = drm_atomic_add_affected_connectors(state, crtc);
		if (ret != 0)
			return ret;

		ret = drm_atomic_add_affected_planes(state, crtc);
		if (ret != 0)
			return ret;
	}

	/*
	 * Iterate over all connectors again, to make sure atomic_check()
	 * has been called on them when a modeset is forced.
	 */
	for_each_oldnew_connector_in_state(state, connector, old_connector_state, new_connector_state, i) {
		const struct drm_connector_helper_funcs *funcs = connector->helper_private;

		if (connectors_mask & BIT(i))
			continue;

		if (funcs->atomic_check)
			ret = funcs->atomic_check(connector, state);
		if (ret)
			return ret;
	}

	/*
	 * Iterate over all connectors again, and add all affected bridges to
	 * the state.
	 */
	for_each_oldnew_connector_in_state(state, connector,
					   old_connector_state,
					   new_connector_state, i) {
		struct drm_encoder *encoder;

		encoder = old_connector_state->best_encoder;
		ret = drm_atomic_add_encoder_bridges(state, encoder);
		if (ret)
			return ret;

		encoder = new_connector_state->best_encoder;
		ret = drm_atomic_add_encoder_bridges(state, encoder);
		if (ret)
			return ret;
	}

	ret = mode_valid(state);
	if (ret)
		return ret;

	return mode_fixup(state);
}
EXPORT_SYMBOL(drm_atomic_helper_check_modeset);

/**
 * drm_atomic_helper_check_plane_state() - Check plane state for validity
 * @plane_state: plane state to check
 * @crtc_state: CRTC state to check
 * @min_scale: minimum @src:@dest scaling factor in 16.16 fixed point
 * @max_scale: maximum @src:@dest scaling factor in 16.16 fixed point
 * @can_position: is it legal to position the plane such that it
 *                doesn't cover the entire CRTC?  This will generally
 *                only be false for primary planes.
 * @can_update_disabled: can the plane be updated while the CRTC
 *                       is disabled?
 *
 * Checks that a desired plane update is valid, and updates various
 * bits of derived state (clipped coordinates etc.). Drivers that provide
 * their own plane handling rather than helper-provided implementations may
 * still wish to call this function to avoid duplication of error checking
 * code.
 *
 * RETURNS:
 * Zero if update appears valid, error code on failure
 */
int drm_atomic_helper_check_plane_state(struct drm_plane_state *plane_state,
					const struct drm_crtc_state *crtc_state,
					int min_scale,
					int max_scale,
					bool can_position,
					bool can_update_disabled)
{
	struct drm_framebuffer *fb = plane_state->fb;
	struct drm_rect *src = &plane_state->src;
	struct drm_rect *dst = &plane_state->dst;
	unsigned int rotation = plane_state->rotation;
	struct drm_rect clip = {};
	int hscale, vscale;

	WARN_ON(plane_state->crtc && plane_state->crtc != crtc_state->crtc);

	*src = drm_plane_state_src(plane_state);
	*dst = drm_plane_state_dest(plane_state);

	if (!fb) {
		plane_state->visible = false;
		return 0;
	}

	/* crtc should only be NULL when disabling (i.e., !fb) */
	if (WARN_ON(!plane_state->crtc)) {
		plane_state->visible = false;
		return 0;
	}

	if (!crtc_state->enable && !can_update_disabled) {
		DRM_DEBUG_KMS("Cannot update plane of a disabled CRTC.\n");
		return -EINVAL;
	}

	drm_rect_rotate(src, fb->width << 16, fb->height << 16, rotation);

	/* Check scaling */
	hscale = drm_rect_calc_hscale(src, dst, min_scale, max_scale);
	vscale = drm_rect_calc_vscale(src, dst, min_scale, max_scale);
	if (hscale < 0 || vscale < 0) {
		DRM_DEBUG_KMS("Invalid scaling of plane\n");
		drm_rect_debug_print("src: ", &plane_state->src, true);
		drm_rect_debug_print("dst: ", &plane_state->dst, false);
		return -ERANGE;
	}

	if (crtc_state->enable)
		drm_mode_get_hv_timing(&crtc_state->mode, &clip.x2, &clip.y2);

	plane_state->visible = drm_rect_clip_scaled(src, dst, &clip);

	drm_rect_rotate_inv(src, fb->width << 16, fb->height << 16, rotation);

	if (!plane_state->visible)
		/*
		 * Plane isn't visible; some drivers can handle this
		 * so we just return success here.  Drivers that can't
		 * (including those that use the primary plane helper's
		 * update function) will return an error from their
		 * update_plane handler.
		 */
		return 0;

	if (!can_position && !drm_rect_equals(dst, &clip)) {
		DRM_DEBUG_KMS("Plane must cover entire CRTC\n");
		drm_rect_debug_print("dst: ", dst, false);
		drm_rect_debug_print("clip: ", &clip, false);
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(drm_atomic_helper_check_plane_state);

/**
 * drm_atomic_helper_check_planes - validate state object for planes changes
 * @dev: DRM device
 * @state: the driver state object
 *
 * Check the state object to see if the requested state is physically possible.
 * This does all the plane update related checks using by calling into the
 * &drm_crtc_helper_funcs.atomic_check and &drm_plane_helper_funcs.atomic_check
 * hooks provided by the driver.
 *
 * It also sets &drm_crtc_state.planes_changed to indicate that a CRTC has
 * updated planes.
 *
 * RETURNS:
 * Zero for success or -errno
 */
int
drm_atomic_helper_check_planes(struct drm_device *dev,
			       struct drm_atomic_state *state)
{
	struct drm_crtc *crtc;
	struct drm_crtc_state *new_crtc_state;
	struct drm_plane *plane;
	struct drm_plane_state *new_plane_state, *old_plane_state;
	int i, ret = 0;

	for_each_oldnew_plane_in_state(state, plane, old_plane_state, new_plane_state, i) {
		const struct drm_plane_helper_funcs *funcs;

		WARN_ON(!drm_modeset_is_locked(&plane->mutex));

		funcs = plane->helper_private;

		drm_atomic_helper_plane_changed(state, old_plane_state, new_plane_state, plane);

		drm_atomic_helper_check_plane_damage(state, new_plane_state);

		if (!funcs || !funcs->atomic_check)
			continue;

		ret = funcs->atomic_check(plane, new_plane_state);
		if (ret) {
			DRM_DEBUG_ATOMIC("[PLANE:%d:%s] atomic driver check failed\n",
					 plane->base.id, plane->name);
			return ret;
		}
	}

	for_each_new_crtc_in_state(state, crtc, new_crtc_state, i) {
		const struct drm_crtc_helper_funcs *funcs;

		funcs = crtc->helper_private;

		if (!funcs || !funcs->atomic_check)
			continue;

		ret = funcs->atomic_check(crtc, new_crtc_state);
		if (ret) {
			DRM_DEBUG_ATOMIC("[CRTC:%d:%s] atomic driver check failed\n",
					 crtc->base.id, crtc->name);
			return ret;
		}
	}

	return ret;
}
EXPORT_SYMBOL(drm_atomic_helper_check_planes);

/**
 * drm_atomic_helper_check - validate state object
 * @dev: DRM device
 * @state: the driver state object
 *
 * Check the state object to see if the requested state is physically possible.
 * Only CRTCs and planes have check callbacks, so for any additional (global)
 * checking that a driver needs it can simply wrap that around this function.
 * Drivers without such needs can directly use this as their
 * &drm_mode_config_funcs.atomic_check callback.
 *
 * This just wraps the two parts of the state checking for planes and modeset
 * state in the default order: First it calls drm_atomic_helper_check_modeset()
 * and then drm_atomic_helper_check_planes(). The assumption is that the
 * @drm_plane_helper_funcs.atomic_check and @drm_crtc_helper_funcs.atomic_check
 * functions depend upon an updated adjusted_mode.clock to e.g. properly compute
 * watermarks.
 *
 * Note that zpos normalization will add all enable planes to the state which
 * might not desired for some drivers.
 * For example enable/disable of a cursor plane which have fixed zpos value
 * would trigger all other enabled planes to be forced to the state change.
 *
 * RETURNS:
 * Zero for success or -errno
 */
int drm_atomic_helper_check(struct drm_device *dev,
			    struct drm_atomic_state *state)
{
	int ret;

	ret = drm_atomic_helper_check_modeset(dev, state);
	if (ret)
		return ret;

	if (dev->mode_config.normalize_zpos) {
		ret = drm_atomic_normalize_zpos(dev, state);
		if (ret)
			return ret;
	}

	ret = drm_atomic_helper_check_planes(dev, state);
	if (ret)
		return ret;

	if (state->legacy_cursor_update)
		state->async_update = !drm_atomic_helper_async_check(dev, state);

	drm_self_refresh_helper_alter_state(state);

	return ret;
}
EXPORT_SYMBOL(drm_atomic_helper_check);

static bool
crtc_needs_disable(struct drm_crtc_state *old_state,
		   struct drm_crtc_state *new_state)
{
	/*
	 * No new_state means the CRTC is off, so the only criteria is whether
	 * it's currently active or in self refresh mode.
	 */
	if (!new_state)
		return drm_atomic_crtc_effectively_active(old_state);

	/*
	 * We need to run through the crtc_funcs->disable() function if the CRTC
	 * is currently on, if it's transitioning to self refresh mode, or if
	 * it's in self refresh mode and needs to be fully disabled.
	 */
	return old_state->active ||
	       (old_state->self_refresh_active && !new_state->enable) ||
	       new_state->self_refresh_active;
}

static void
disable_outputs(struct drm_device *dev, struct drm_atomic_state *old_state)
{
	struct drm_connector *connector;
	struct drm_connector_state *old_conn_state, *new_conn_state;
	struct drm_crtc *crtc;
	struct drm_crtc_state *old_crtc_state, *new_crtc_state;
	int i;

	for_each_oldnew_connector_in_state(old_state, connector, old_conn_state, new_conn_state, i) {
		const struct drm_encoder_helper_funcs *funcs;
		struct drm_encoder *encoder;
		struct drm_bridge *bridge;

		/* Shut down everything that's in the changeset and currently
		 * still on. So need to check the old, saved state. */
		if (!old_conn_state->crtc)
			continue;

		old_crtc_state = drm_atomic_get_old_crtc_state(old_state, old_conn_state->crtc);

		if (new_conn_state->crtc)
			new_crtc_state = drm_atomic_get_new_crtc_state(
						old_state,
						new_conn_state->crtc);
		else
			new_crtc_state = NULL;

		if (!crtc_needs_disable(old_crtc_state, new_crtc_state) ||
		    !drm_atomic_crtc_needs_modeset(old_conn_state->crtc->state))
			continue;

		encoder = old_conn_state->best_encoder;

		/* We shouldn't get this far if we didn't previously have
		 * an encoder.. but WARN_ON() rather than explode.
		 */
		if (WARN_ON(!encoder))
			continue;

		funcs = encoder->helper_private;

		DRM_DEBUG_ATOMIC("disabling [ENCODER:%d:%s]\n",
				 encoder->base.id, encoder->name);

		/*
		 * Each encoder has at most one connector (since we always steal
		 * it away), so we won't call disable hooks twice.
		 */
		bridge = drm_bridge_chain_get_first_bridge(encoder);
		drm_atomic_bridge_chain_disable(bridge, old_state);

		/* Right function depends upon target state. */
		if (funcs) {
			if (funcs->atomic_disable)
				funcs->atomic_disable(encoder, old_state);
			else if (new_conn_state->crtc && funcs->prepare)
				funcs->prepare(encoder);
			else if (funcs->disable)
				funcs->disable(encoder);
			else if (funcs->dpms)
				funcs->dpms(encoder, DRM_MODE_DPMS_OFF);
		}

		drm_atomic_bridge_chain_post_disable(bridge, old_state);
	}

	for_each_oldnew_crtc_in_state(old_state, crtc, old_crtc_state, new_crtc_state, i) {
		const struct drm_crtc_helper_funcs *funcs;
		int ret;

		/* Shut down everything that needs a full modeset. */
		if (!drm_atomic_crtc_needs_modeset(new_crtc_state))
			continue;

		if (!crtc_needs_disable(old_crtc_state, new_crtc_state))
			continue;

		funcs = crtc->helper_private;

		DRM_DEBUG_ATOMIC("disabling [CRTC:%d:%s]\n",
				 crtc->base.id, crtc->name);


		/* Right function depends upon target state. */
		if (new_crtc_state->enable && funcs->prepare)
			funcs->prepare(crtc);
		else if (funcs->atomic_disable)
			funcs->atomic_disable(crtc, old_crtc_state);
		else if (funcs->disable)
			funcs->disable(crtc);
		else if (funcs->dpms)
			funcs->dpms(crtc, DRM_MODE_DPMS_OFF);

		if (!drm_dev_has_vblank(dev))
			continue;

		ret = drm_crtc_vblank_get(crtc);
		WARN_ONCE(ret != -EINVAL, "driver forgot to call drm_crtc_vblank_off()\n");
		if (ret == 0)
			drm_crtc_vblank_put(crtc);
	}
}

/**
 * drm_atomic_helper_update_legacy_modeset_state - update legacy modeset state
 * @dev: DRM device
 * @old_state: atomic state object with old state structures
 *
 * This function updates all the various legacy modeset state pointers in
 * connectors, encoders and CRTCs.
 *
 * Drivers can use this for building their own atomic commit if they don't have
 * a pure helper-based modeset implementation.
 *
 * Since these updates are not synchronized with lockings, only code paths
 * called from &drm_mode_config_helper_funcs.atomic_commit_tail can look at the
 * legacy state filled out by this helper. Defacto this means this helper and
 * the legacy state pointers are only really useful for transitioning an
 * existing driver to the atomic world.
 */
void
drm_atomic_helper_update_legacy_modeset_state(struct drm_device *dev,
					      struct drm_atomic_state *old_state)
{
	struct drm_connector *connector;
	struct drm_connector_state *old_conn_state, *new_conn_state;
	struct drm_crtc *crtc;
	struct drm_crtc_state *new_crtc_state;
	int i;

	/* clear out existing links and update dpms */
	for_each_oldnew_connector_in_state(old_state, connector, old_conn_state, new_conn_state, i) {
		if (connector->encoder) {
			WARN_ON(!connector->encoder->crtc);

			connector->encoder->crtc = NULL;
			connector->encoder = NULL;
		}

		crtc = new_conn_state->crtc;
		if ((!crtc && old_conn_state->crtc) ||
		    (crtc && drm_atomic_crtc_needs_modeset(crtc->state))) {
			int mode = DRM_MODE_DPMS_OFF;

			if (crtc && crtc->state->active)
				mode = DRM_MODE_DPMS_ON;

			connector->dpms = mode;
		}
	}

	/* set new links */
	for_each_new_connector_in_state(old_state, connector, new_conn_state, i) {
		if (!new_conn_state->crtc)
			continue;

		if (WARN_ON(!new_conn_state->best_encoder))
			continue;

		connector->encoder = new_conn_state->best_encoder;
		connector->encoder->crtc = new_conn_state->crtc;
	}

	/* set legacy state in the crtc structure */
	for_each_new_crtc_in_state(old_state, crtc, new_crtc_state, i) {
		struct drm_plane *primary = crtc->primary;
		struct drm_plane_state *new_plane_state;

		crtc->mode = new_crtc_state->mode;
		crtc->enabled = new_crtc_state->enable;

		new_plane_state =
			drm_atomic_get_new_plane_state(old_state, primary);

		if (new_plane_state && new_plane_state->crtc == crtc) {
			crtc->x = new_plane_state->src_x >> 16;
			crtc->y = new_plane_state->src_y >> 16;
		}
	}
}
EXPORT_SYMBOL(drm_atomic_helper_update_legacy_modeset_state);

/**
 * drm_atomic_helper_calc_timestamping_constants - update vblank timestamping constants
 * @state: atomic state object
 *
 * Updates the timestamping constants used for precise vblank timestamps
 * by calling drm_calc_timestamping_constants() for all enabled crtcs in @state.
 */
void drm_atomic_helper_calc_timestamping_constants(struct drm_atomic_state *state)
{
	struct drm_crtc_state *new_crtc_state;
	struct drm_crtc *crtc;
	int i;

	for_each_new_crtc_in_state(state, crtc, new_crtc_state, i) {
		if (new_crtc_state->enable)
			drm_calc_timestamping_constants(crtc,
							&new_crtc_state->adjusted_mode);
	}
}
EXPORT_SYMBOL(drm_atomic_helper_calc_timestamping_constants);

static void
crtc_set_mode(struct drm_device *dev, struct drm_atomic_state *old_state)
{
	struct drm_crtc *crtc;
	struct drm_crtc_state *new_crtc_state;
	struct drm_connector *connector;
	struct drm_connector_state *new_conn_state;
	int i;

	for_each_new_crtc_in_state(old_state, crtc, new_crtc_state, i) {
		const struct drm_crtc_helper_funcs *funcs;

		if (!new_crtc_state->mode_changed)
			continue;

		funcs = crtc->helper_private;

		if (new_crtc_state->enable && funcs->mode_set_nofb) {
			DRM_DEBUG_ATOMIC("modeset on [CRTC:%d:%s]\n",
					 crtc->base.id, crtc->name);

			funcs->mode_set_nofb(crtc);
		}
	}

	for_each_new_connector_in_state(old_state, connector, new_conn_state, i) {
		const struct drm_encoder_helper_funcs *funcs;
		struct drm_encoder *encoder;
		struct drm_display_mode *mode, *adjusted_mode;
		struct drm_bridge *bridge;

		if (!new_conn_state->best_encoder)
			continue;

		encoder = new_conn_state->best_encoder;
		funcs = encoder->helper_private;
		new_crtc_state = new_conn_state->crtc->state;
		mode = &new_crtc_state->mode;
		adjusted_mode = &new_crtc_state->adjusted_mode;

		if (!new_crtc_state->mode_changed)
			continue;

		DRM_DEBUG_ATOMIC("modeset on [ENCODER:%d:%s]\n",
				 encoder->base.id, encoder->name);

		/*
		 * Each encoder has at most one connector (since we always steal
		 * it away), so we won't call mode_set hooks twice.
		 */
		if (funcs && funcs->atomic_mode_set) {
			funcs->atomic_mode_set(encoder, new_crtc_state,
					       new_conn_state);
		} else if (funcs && funcs->mode_set) {
			funcs->mode_set(encoder, mode, adjusted_mode);
		}

		bridge = drm_bridge_chain_get_first_bridge(encoder);
		drm_bridge_chain_mode_set(bridge, mode, adjusted_mode);
	}
}

/**
 * drm_atomic_helper_commit_modeset_disables - modeset commit to disable outputs
 * @dev: DRM device
 * @old_state: atomic state object with old state structures
 *
 * This function shuts down all the outputs that need to be shut down and
 * prepares them (if required) with the new mode.
 *
 * For compatibility with legacy CRTC helpers this should be called before
 * drm_atomic_helper_commit_planes(), which is what the default commit function
 * does. But drivers with different needs can group the modeset commits together
 * and do the plane commits at the end. This is useful for drivers doing runtime
 * PM since planes updates then only happen when the CRTC is actually enabled.
 */
void drm_atomic_helper_commit_modeset_disables(struct drm_device *dev,
					       struct drm_atomic_state *old_state)
{
	disable_outputs(dev, old_state);

	drm_atomic_helper_update_legacy_modeset_state(dev, old_state);
	drm_atomic_helper_calc_timestamping_constants(old_state);

	crtc_set_mode(dev, old_state);
}
EXPORT_SYMBOL(drm_atomic_helper_commit_modeset_disables);

static void drm_atomic_helper_commit_writebacks(struct drm_device *dev,
						struct drm_atomic_state *old_state)
{
	struct drm_connector *connector;
	struct drm_connector_state *new_conn_state;
	int i;

	for_each_new_connector_in_state(old_state, connector, new_conn_state, i) {
		const struct drm_connector_helper_funcs *funcs;

		funcs = connector->helper_private;
		if (!funcs->atomic_commit)
			continue;

		if (new_conn_state->writeback_job && new_conn_state->writeback_job->fb) {
			WARN_ON(connector->connector_type != DRM_MODE_CONNECTOR_WRITEBACK);
			funcs->atomic_commit(connector, new_conn_state);
		}
	}
}

/**
 * drm_atomic_helper_commit_modeset_enables - modeset commit to enable outputs
 * @dev: DRM device
 * @old_state: atomic state object with old state structures
 *
 * This function enables all the outputs with the new configuration which had to
 * be turned off for the update.
 *
 * For compatibility with legacy CRTC helpers this should be called after
 * drm_atomic_helper_commit_planes(), which is what the default commit function
 * does. But drivers with different needs can group the modeset commits together
 * and do the plane commits at the end. This is useful for drivers doing runtime
 * PM since planes updates then only happen when the CRTC is actually enabled.
 */
void drm_atomic_helper_commit_modeset_enables(struct drm_device *dev,
					      struct drm_atomic_state *old_state)
{
	struct drm_crtc *crtc;
	struct drm_crtc_state *old_crtc_state;
	struct drm_crtc_state *new_crtc_state;
	struct drm_connector *connector;
	struct drm_connector_state *new_conn_state;
	int i;

	for_each_oldnew_crtc_in_state(old_state, crtc, old_crtc_state, new_crtc_state, i) {
		const struct drm_crtc_helper_funcs *funcs;

		/* Need to filter out CRTCs where only planes change. */
		if (!drm_atomic_crtc_needs_modeset(new_crtc_state))
			continue;

		if (!new_crtc_state->active)
			continue;

		funcs = crtc->helper_private;

		if (new_crtc_state->enable) {
			DRM_DEBUG_ATOMIC("enabling [CRTC:%d:%s]\n",
					 crtc->base.id, crtc->name);
			if (funcs->atomic_enable)
				funcs->atomic_enable(crtc, old_crtc_state);
			else if (funcs->commit)
				funcs->commit(crtc);
		}
	}

	for_each_new_connector_in_state(old_state, connector, new_conn_state, i) {
		const struct drm_encoder_helper_funcs *funcs;
		struct drm_encoder *encoder;
		struct drm_bridge *bridge;

		if (!new_conn_state->best_encoder)
			continue;

		if (!new_conn_state->crtc->state->active ||
		    !drm_atomic_crtc_needs_modeset(new_conn_state->crtc->state))
			continue;

		encoder = new_conn_state->best_encoder;
		funcs = encoder->helper_private;

		DRM_DEBUG_ATOMIC("enabling [ENCODER:%d:%s]\n",
				 encoder->base.id, encoder->name);

		/*
		 * Each encoder has at most one connector (since we always steal
		 * it away), so we won't call enable hooks twice.
		 */
		bridge = drm_bridge_chain_get_first_bridge(encoder);
		drm_atomic_bridge_chain_pre_enable(bridge, old_state);

		if (funcs) {
			if (funcs->atomic_enable)
				funcs->atomic_enable(encoder, old_state);
			else if (funcs->enable)
				funcs->enable(encoder);
			else if (funcs->commit)
				funcs->commit(encoder);
		}

		drm_atomic_bridge_chain_enable(bridge, old_state);
	}

	drm_atomic_helper_commit_writebacks(dev, old_state);
}
EXPORT_SYMBOL(drm_atomic_helper_commit_modeset_enables);

/**
 * drm_atomic_helper_wait_for_fences - wait for fences stashed in plane state
 * @dev: DRM device
 * @state: atomic state object with old state structures
 * @pre_swap: If true, do an interruptible wait, and @state is the new state.
 * 	Otherwise @state is the old state.
 *
 * For implicit sync, driver should fish the exclusive fence out from the
 * incoming fb's and stash it in the drm_plane_state.  This is called after
 * drm_atomic_helper_swap_state() so it uses the current plane state (and
 * just uses the atomic state to find the changed planes)
 *
 * Note that @pre_swap is needed since the point where we block for fences moves
 * around depending upon whether an atomic commit is blocking or
 * non-blocking. For non-blocking commit all waiting needs to happen after
 * drm_atomic_helper_swap_state() is called, but for blocking commits we want
 * to wait **before** we do anything that can't be easily rolled back. That is
 * before we call drm_atomic_helper_swap_state().
 *
 * Returns zero if success or < 0 if dma_fence_wait() fails.
 */
int drm_atomic_helper_wait_for_fences(struct drm_device *dev,
				      struct drm_atomic_state *state,
				      bool pre_swap)
{
	struct drm_plane *plane;
	struct drm_plane_state *new_plane_state;
	int i, ret;

	for_each_new_plane_in_state(state, plane, new_plane_state, i) {
		if (!new_plane_state->fence)
			continue;

		WARN_ON(!new_plane_state->fb);

		/*
		 * If waiting for fences pre-swap (ie: nonblock), userspace can
		 * still interrupt the operation. Instead of blocking until the
		 * timer expires, make the wait interruptible.
		 */
		ret = dma_fence_wait(new_plane_state->fence, pre_swap);
		if (ret)
			return ret;

		dma_fence_put(new_plane_state->fence);
		new_plane_state->fence = NULL;
	}

	return 0;
}
EXPORT_SYMBOL(drm_atomic_helper_wait_for_fences);

/**
 * drm_atomic_helper_wait_for_vblanks - wait for vblank on CRTCs
 * @dev: DRM device
 * @old_state: atomic state object with old state structures
 *
 * Helper to, after atomic commit, wait for vblanks on all affected
 * CRTCs (ie. before cleaning up old framebuffers using
 * drm_atomic_helper_cleanup_planes()). It will only wait on CRTCs where the
 * framebuffers have actually changed to optimize for the legacy cursor and
 * plane update use-case.
 *
 * Drivers using the nonblocking commit tracking support initialized by calling
 * drm_atomic_helper_setup_commit() should look at
 * drm_atomic_helper_wait_for_flip_done() as an alternative.
 */
void
drm_atomic_helper_wait_for_vblanks(struct drm_device *dev,
		struct drm_atomic_state *old_state)
{
	struct drm_crtc *crtc;
	struct drm_crtc_state *old_crtc_state, *new_crtc_state;
	int i, ret;
	unsigned crtc_mask = 0;

	 /*
	  * Legacy cursor ioctls are completely unsynced, and userspace
	  * relies on that (by doing tons of cursor updates).
	  */
	if (old_state->legacy_cursor_update)
		return;

	for_each_oldnew_crtc_in_state(old_state, crtc, old_crtc_state, new_crtc_state, i) {
		if (!new_crtc_state->active)
			continue;

		ret = drm_crtc_vblank_get(crtc);
		if (ret != 0)
			continue;

		crtc_mask |= drm_crtc_mask(crtc);
		old_state->crtcs[i].last_vblank_count = drm_crtc_vblank_count(crtc);
	}

	for_each_old_crtc_in_state(old_state, crtc, old_crtc_state, i) {
		if (!(crtc_mask & drm_crtc_mask(crtc)))
			continue;

		ret = wait_event_timeout(dev->vblank[i].queue,
				old_state->crtcs[i].last_vblank_count !=
					drm_crtc_vblank_count(crtc),
				msecs_to_jiffies(100));

		WARN(!ret, "[CRTC:%d:%s] vblank wait timed out\n",
		     crtc->base.id, crtc->name);

		drm_crtc_vblank_put(crtc);
	}
}
EXPORT_SYMBOL(drm_atomic_helper_wait_for_vblanks);

/**
 * drm_atomic_helper_wait_for_flip_done - wait for all page flips to be done
 * @dev: DRM device
 * @old_state: atomic state object with old state structures
 *
 * Helper to, after atomic commit, wait for page flips on all affected
 * crtcs (ie. before cleaning up old framebuffers using
 * drm_atomic_helper_cleanup_planes()). Compared to
 * drm_atomic_helper_wait_for_vblanks() this waits for the completion on all
 * CRTCs, assuming that cursors-only updates are signalling their completion
 * immediately (or using a different path).
 *
 * This requires that drivers use the nonblocking commit tracking support
 * initialized using drm_atomic_helper_setup_commit().
 */
void drm_atomic_helper_wait_for_flip_done(struct drm_device *dev,
					  struct drm_atomic_state *old_state)
{
	struct drm_crtc *crtc;
	int i;

	for (i = 0; i < dev->mode_config.num_crtc; i++) {
		struct drm_crtc_commit *commit = old_state->crtcs[i].commit;
		int ret;

		crtc = old_state->crtcs[i].ptr;

		if (!crtc || !commit)
			continue;

		ret = wait_for_completion_timeout(&commit->flip_done, 10 * HZ);
		if (ret == 0)
			DRM_ERROR("[CRTC:%d:%s] flip_done timed out\n",
				  crtc->base.id, crtc->name);
	}

	if (old_state->fake_commit)
		complete_all(&old_state->fake_commit->flip_done);
}
EXPORT_SYMBOL(drm_atomic_helper_wait_for_flip_done);

/**
 * drm_atomic_helper_commit_tail - commit atomic update to hardware
 * @old_state: atomic state object with old state structures
 *
 * This is the default implementation for the
 * &drm_mode_config_helper_funcs.atomic_commit_tail hook, for drivers
 * that do not support runtime_pm or do not need the CRTC to be
 * enabled to perform a commit. Otherwise, see
 * drm_atomic_helper_commit_tail_rpm().
 *
 * Note that the default ordering of how the various stages are called is to
 * match the legacy modeset helper library closest.
 */
void drm_atomic_helper_commit_tail(struct drm_atomic_state *old_state)
{
	struct drm_device *dev = old_state->dev;

	drm_atomic_helper_commit_modeset_disables(dev, old_state);

	drm_atomic_helper_commit_planes(dev, old_state, 0);

	drm_atomic_helper_commit_modeset_enables(dev, old_state);

	drm_atomic_helper_fake_vblank(old_state);

	drm_atomic_helper_commit_hw_done(old_state);

	drm_atomic_helper_wait_for_vblanks(dev, old_state);

	drm_atomic_helper_cleanup_planes(dev, old_state);
}
EXPORT_SYMBOL(drm_atomic_helper_commit_tail);

/**
 * drm_atomic_helper_commit_tail_rpm - commit atomic update to hardware
 * @old_state: new modeset state to be committed
 *
 * This is an alternative implementation for the
 * &drm_mode_config_helper_funcs.atomic_commit_tail hook, for drivers
 * that support runtime_pm or need the CRTC to be enabled to perform a
 * commit. Otherwise, one should use the default implementation
 * drm_atomic_helper_commit_tail().
 */
void drm_atomic_helper_commit_tail_rpm(struct drm_atomic_state *old_state)
{
	struct drm_device *dev = old_state->dev;

	drm_atomic_helper_commit_modeset_disables(dev, old_state);

	drm_atomic_helper_commit_modeset_enables(dev, old_state);

	drm_atomic_helper_commit_planes(dev, old_state,
					DRM_PLANE_COMMIT_ACTIVE_ONLY);

	drm_atomic_helper_fake_vblank(old_state);

	drm_atomic_helper_commit_hw_done(old_state);

	drm_atomic_helper_wait_for_vblanks(dev, old_state);

	drm_atomic_helper_cleanup_planes(dev, old_state);
}
EXPORT_SYMBOL(drm_atomic_helper_commit_tail_rpm);

static void commit_tail(struct drm_atomic_state *old_state)
{
	struct drm_device *dev = old_state->dev;
	const struct drm_mode_config_helper_funcs *funcs;
	struct drm_crtc_state *new_crtc_state;
	struct drm_crtc *crtc;
	ktime_t start;
	s64 commit_time_ms;
	unsigned int i, new_self_refresh_mask = 0;

	funcs = dev->mode_config.helper_private;

	/*
	 * We're measuring the _entire_ commit, so the time will vary depending
	 * on how many fences and objects are involved. For the purposes of self
	 * refresh, this is desirable since it'll give us an idea of how
	 * congested things are. This will inform our decision on how often we
	 * should enter self refresh after idle.
	 *
	 * These times will be averaged out in the self refresh helpers to avoid
	 * overreacting over one outlier frame
	 */
	start = ktime_get();

	drm_atomic_helper_wait_for_fences(dev, old_state, false);

	drm_atomic_helper_wait_for_dependencies(old_state);

	/*
	 * We cannot safely access new_crtc_state after
	 * drm_atomic_helper_commit_hw_done() so figure out which crtc's have
	 * self-refresh active beforehand:
	 */
	for_each_new_crtc_in_state(old_state, crtc, new_crtc_state, i)
		if (new_crtc_state->self_refresh_active)
			new_self_refresh_mask |= BIT(i);

	if (funcs && funcs->atomic_commit_tail)
		funcs->atomic_commit_tail(old_state);
	else
		drm_atomic_helper_commit_tail(old_state);

	commit_time_ms = ktime_ms_delta(ktime_get(), start);
	if (commit_time_ms > 0)
		drm_self_refresh_helper_update_avg_times(old_state,
						 (unsigned long)commit_time_ms,
						 new_self_refresh_mask);

	drm_atomic_helper_commit_cleanup_done(old_state);

	drm_atomic_state_put(old_state);
}

static void commit_work(struct work_struct *work)
{
	struct drm_atomic_state *state = container_of(work,
						      struct drm_atomic_state,
						      commit_work);
	commit_tail(state);
}

/**
 * drm_atomic_helper_async_check - check if state can be commited asynchronously
 * @dev: DRM device
 * @state: the driver state object
 *
 * This helper will check if it is possible to commit the state asynchronously.
 * Async commits are not supposed to swap the states like normal sync commits
 * but just do in-place changes on the current state.
 *
 * It will return 0 if the commit can happen in an asynchronous fashion or error
 * if not. Note that error just mean it can't be commited asynchronously, if it
 * fails the commit should be treated like a normal synchronous commit.
 */
int drm_atomic_helper_async_check(struct drm_device *dev,
				   struct drm_atomic_state *state)
{
	struct drm_crtc *crtc;
	struct drm_crtc_state *crtc_state;
	struct drm_plane *plane = NULL;
	struct drm_plane_state *old_plane_state = NULL;
	struct drm_plane_state *new_plane_state = NULL;
	const struct drm_plane_helper_funcs *funcs;
	int i, n_planes = 0;

	for_each_new_crtc_in_state(state, crtc, crtc_state, i) {
		if (drm_atomic_crtc_needs_modeset(crtc_state))
			return -EINVAL;
	}

	for_each_oldnew_plane_in_state(state, plane, old_plane_state, new_plane_state, i)
		n_planes++;

	/* FIXME: we support only single plane updates for now */
	if (n_planes != 1)
		return -EINVAL;

	if (!new_plane_state->crtc ||
	    old_plane_state->crtc != new_plane_state->crtc)
		return -EINVAL;

	funcs = plane->helper_private;
	if (!funcs->atomic_async_update)
		return -EINVAL;

	if (new_plane_state->fence)
		return -EINVAL;

	/*
	 * Don't do an async update if there is an outstanding commit modifying
	 * the plane.  This prevents our async update's changes from getting
	 * overridden by a previous synchronous update's state.
	 */
	if (old_plane_state->commit &&
	    !try_wait_for_completion(&old_plane_state->commit->hw_done))
		return -EBUSY;

	return funcs->atomic_async_check(plane, new_plane_state);
}
EXPORT_SYMBOL(drm_atomic_helper_async_check);

/**
 * drm_atomic_helper_async_commit - commit state asynchronously
 * @dev: DRM device
 * @state: the driver state object
 *
 * This function commits a state asynchronously, i.e., not vblank
 * synchronized. It should be used on a state only when
 * drm_atomic_async_check() succeeds. Async commits are not supposed to swap
 * the states like normal sync commits, but just do in-place changes on the
 * current state.
 *
 * TODO: Implement full swap instead of doing in-place changes.
 */
void drm_atomic_helper_async_commit(struct drm_device *dev,
				    struct drm_atomic_state *state)
{
	struct drm_plane *plane;
	struct drm_plane_state *plane_state;
	const struct drm_plane_helper_funcs *funcs;
	int i;

	for_each_new_plane_in_state(state, plane, plane_state, i) {
		struct drm_framebuffer *new_fb = plane_state->fb;
		struct drm_framebuffer *old_fb = plane->state->fb;

		funcs = plane->helper_private;
		funcs->atomic_async_update(plane, plane_state);

		/*
		 * ->atomic_async_update() is supposed to update the
		 * plane->state in-place, make sure at least common
		 * properties have been properly updated.
		 */
		WARN_ON_ONCE(plane->state->fb != new_fb);
		WARN_ON_ONCE(plane->state->crtc_x != plane_state->crtc_x);
		WARN_ON_ONCE(plane->state->crtc_y != plane_state->crtc_y);
		WARN_ON_ONCE(plane->state->src_x != plane_state->src_x);
		WARN_ON_ONCE(plane->state->src_y != plane_state->src_y);

		/*
		 * Make sure the FBs have been swapped so that cleanups in the
		 * new_state performs a cleanup in the old FB.
		 */
		WARN_ON_ONCE(plane_state->fb != old_fb);
	}
}
EXPORT_SYMBOL(drm_atomic_helper_async_commit);

/**
 * drm_atomic_helper_commit - commit validated state object
 * @dev: DRM device
 * @state: the driver state object
 * @nonblock: whether nonblocking behavior is requested.
 *
 * This function commits a with drm_atomic_helper_check() pre-validated state
 * object. This can still fail when e.g. the framebuffer reservation fails. This
 * function implements nonblocking commits, using
 * drm_atomic_helper_setup_commit() and related functions.
 *
 * Committing the actual hardware state is done through the
 * &drm_mode_config_helper_funcs.atomic_commit_tail callback, or its default
 * implementation drm_atomic_helper_commit_tail().
 *
 * RETURNS:
 * Zero for success or -errno.
 */
int drm_atomic_helper_commit(struct drm_device *dev,
			     struct drm_atomic_state *state,
			     bool nonblock)
{
	int ret;

	if (state->async_update) {
		ret = drm_atomic_helper_prepare_planes(dev, state);
		if (ret)
			return ret;

		drm_atomic_helper_async_commit(dev, state);
		drm_atomic_helper_cleanup_planes(dev, state);

		return 0;
	}

	ret = drm_atomic_helper_setup_commit(state, nonblock);
	if (ret)
		return ret;

	INIT_WORK(&state->commit_work, commit_work);

	ret = drm_atomic_helper_prepare_planes(dev, state);
	if (ret)
		return ret;

	if (!nonblock) {
		ret = drm_atomic_helper_wait_for_fences(dev, state, true);
		if (ret)
			goto err;
	}

	/*
	 * This is the point of no return - everything below never fails except
	 * when the hw goes bonghits. Which means we can commit the new state on
	 * the software side now.
	 */

	ret = drm_atomic_helper_swap_state(state, true);
	if (ret)
		goto err;

	/*
	 * Everything below can be run asynchronously without the need to grab
	 * any modeset locks at all under one condition: It must be guaranteed
	 * that the asynchronous work has either been cancelled (if the driver
	 * supports it, which at least requires that the framebuffers get
	 * cleaned up with drm_atomic_helper_cleanup_planes()) or completed
	 * before the new state gets committed on the software side with
	 * drm_atomic_helper_swap_state().
	 *
	 * This scheme allows new atomic state updates to be prepared and
	 * checked in parallel to the asynchronous completion of the previous
	 * update. Which is important since compositors need to figure out the
	 * composition of the next frame right after having submitted the
	 * current layout.
	 *
	 * NOTE: Commit work has multiple phases, first hardware commit, then
	 * cleanup. We want them to overlap, hence need system_unbound_wq to
	 * make sure work items don't artificially stall on each another.
	 */

	drm_atomic_state_get(state);
	if (nonblock)
		queue_work(system_unbound_wq, &state->commit_work);
	else
		commit_tail(state);

	return 0;

err:
	drm_atomic_helper_cleanup_planes(dev, state);
	return ret;
}
EXPORT_SYMBOL(drm_atomic_helper_commit);

/**
 * DOC: implementing nonblocking commit
 *
 * Nonblocking atomic commits should use struct &drm_crtc_commit to sequence
 * different operations against each another. Locks, especially struct
 * &drm_modeset_lock, should not be held in worker threads or any other
 * asynchronous context used to commit the hardware state.
 *
 * drm_atomic_helper_commit() implements the recommended sequence for
 * nonblocking commits, using drm_atomic_helper_setup_commit() internally:
 *
 * 1. Run drm_atomic_helper_prepare_planes(). Since this can fail and we
 * need to propagate out of memory/VRAM errors to userspace, it must be called
 * synchronously.
 *
 * 2. Synchronize with any outstanding nonblocking commit worker threads which
 * might be affected by the new state update. This is handled by
 * drm_atomic_helper_setup_commit().
 *
 * Asynchronous workers need to have sufficient parallelism to be able to run
 * different atomic commits on different CRTCs in parallel. The simplest way to
 * achieve this is by running them on the &system_unbound_wq work queue. Note
 * that drivers are not required to split up atomic commits and run an
 * individual commit in parallel - userspace is supposed to do that if it cares.
 * But it might be beneficial to do that for modesets, since those necessarily
 * must be done as one global operation, and enabling or disabling a CRTC can
 * take a long time. But even that is not required.
 *
 * IMPORTANT: A &drm_atomic_state update for multiple CRTCs is sequenced
 * against all CRTCs therein. Therefore for atomic state updates which only flip
 * planes the driver must not get the struct &drm_crtc_state of unrelated CRTCs
 * in its atomic check code: This would prevent committing of atomic updates to
 * multiple CRTCs in parallel. In general, adding additional state structures
 * should be avoided as much as possible, because this reduces parallelism in
 * (nonblocking) commits, both due to locking and due to commit sequencing
 * requirements.
 *
 * 3. The software state is updated synchronously with
 * drm_atomic_helper_swap_state(). Doing this under the protection of all modeset
 * locks means concurrent callers never see inconsistent state. Note that commit
 * workers do not hold any locks; their access is only coordinated through
 * ordering. If workers would access state only through the pointers in the
 * free-standing state objects (currently not the case for any driver) then even
 * multiple pending commits could be in-flight at the same time.
 *
 * 4. Schedule a work item to do all subsequent steps, using the split-out
 * commit helpers: a) pre-plane commit b) plane commit c) post-plane commit and
 * then cleaning up the framebuffers after the old framebuffer is no longer
 * being displayed. The scheduled work should synchronize against other workers
 * using the &drm_crtc_commit infrastructure as needed. See
 * drm_atomic_helper_setup_commit() for more details.
 */

