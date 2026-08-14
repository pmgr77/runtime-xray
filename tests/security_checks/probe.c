/**
 * @file    probe.c
 * @brief   Minimal executable used for RuntimeXRay security regression tests.
 *
 * This program does nothing; it exists only to be compiled with various
 * security flags (NX, PIE, RELRO) so the xray tool can be tested.
 *
 * @author  Peter Magram
 * @date    2026-08-14
 * @copyright Copyright 2026 Peter Magram.
 * @license Apache-2.0 (see LICENSE file in the repository root)
 */

/* Copyright 2026 Peter Magram
 *
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

int main(void) {
    return 0;
}