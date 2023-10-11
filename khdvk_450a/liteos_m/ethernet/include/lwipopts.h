/*
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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

#ifndef GD_PORT_LWIPOPTS_H
#define GD_PORT_LWIPOPTS_H

#include_next "lwip/lwipopts.h"

#undef ETH_PAD_SIZE
#define ETH_PAD_SIZE 0

#define LWIP_SOCKET_SELECT_FUNC 1

#endif /* GD_PORT_LWIPOPTS_H */
