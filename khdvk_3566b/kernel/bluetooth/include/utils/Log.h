/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef BT_VENDOR_LOG_H
#define BT_VENDOR_LOG_H
#include <stdarg.h>
#include <stdio.h>
#include "hilog/log.h"
#include "time.h"

// #define VENDOR_DEBUG_2_FILE

#ifdef VENDOR_DEBUG_2_FILE
static void Print(const char *fmt, ...)
{
    FILE *fp = fopen("/data/btvendor.log", "a+");

    int nFileLen = ftell(fp);

    int ret;
    char buf[1024] = {0};
    if (fp != 0) {
        time_t timep;
        time(&timep);

        struct tm *p;
        p = gmtime(&timep);
        ret = sprintf(
            buf, "%04d-%02d-%02d %02d:%02d:%02d VENDOR:", 0X76C + p->tm_year,
            1 + p->tm_mon, p->tm_mday, 0X8 + p->tm_hour, p->tm_min, p->tm_sec);
        fwrite(buf, 1, ret, fp);

        va_list ap;
        va_start(ap, fmt);
        ret = vsprintf(buf, fmt, ap);
        va_end(ap);

        buf[ret] = '\n';
        fwrite(buf, 1, ret + 1, fp);
    }
    fclose(fp);
}

#define HILOGD(...) Print(__VA_ARGS__)
#define HILOGI(...) Print(__VA_ARGS__)
#define HILOGW(...) Print(__VA_ARGS__)
#define HILOGE(...) Print(__VA_ARGS__)

#else

#define HILOGD(...)                                                            \
    HiLogPrint(LOG_CORE, LOG_DEBUG, LOG_DOMAIN, "BTVENDOR", __VA_ARGS__)
#define HILOGI(...)                                                            \
    HiLogPrint(LOG_CORE, LOG_INFO, LOG_DOMAIN, "BTVENDOR", __VA_ARGS__)
#define HILOGW(...)                                                            \
    HiLogPrint(LOG_CORE, LOG_WARN, LOG_DOMAIN, "BTVENDOR", __VA_ARGS__)
#define HILOGE(...)                                                            \
    HiLogPrint(LOG_CORE, LOG_ERROR, LOG_DOMAIN, "BTVENDOR", __VA_ARGS__)
#endif

#endif // #define BT_VENDOR_LOG_H