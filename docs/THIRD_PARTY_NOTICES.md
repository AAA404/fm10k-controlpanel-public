# Third-party notices

The FM10000 eye acquisition protocol in `hardware/native/fm10k_eye_scan.c` is adapted from Avago AAPL CORE 2.4.0. The following notice applies to that code and its binary distribution.

```text
AAPL CORE Revision: 2.4.0

Copyright (c) 2014-2016 Avago Technologies. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

Other NetLab notices are retained in `vendor/netlab/NOTICE` and `vendor/netlab/LICENSE`. The proprietary SDK is supplied separately.

## License boundaries

Original project code is licensed under Apache-2.0; see the root LICENSE and NOTICE. The retained Linux driver under `hardware/reference/driver/fm10k-uio-6.12.101-ies2/` is GPL-2.0-only, with its full license in COPYING and its original Intel notices intact. The project license does not replace the AAPL terms above.

`SOURCE_MANIFEST.json` records original import digests and separately supplied inputs. NetLab is derived from the Apache-2.0 project at https://github.com/netlab-switch/netlab-os. The driver source was imported through https://github.com/Sakana-bot/pe31625g24dira-switch-stack and retains its per-file GPL declarations; no general license is inferred for that upstream project's other files.

Manufacturer platform configurations, proprietary IES headers/libraries and reference eye firmware are not distributed here. Their hashes identify compatible inputs and do not grant rights to those materials. Runtime Python and frontend dependencies retain the licenses declared by their respective upstream projects.
