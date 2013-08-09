/*
 * The libmalelf is an evil library that could be used for good! It was
 * developed with the intent to assist in the process of infecting
 * binaries and provide a safe way to analyze malwares.
 *
 * Evil using this library is the responsibility of the programmer.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <malelf/types.h>
#include <malelf/binary.h>
#include <malelf/util.h>
#include <malelf/error.h>
#include <malelf/debug.h>

/**
 * Patch a dword in binary at specified address.
 *
 * Patch the binary data in the offset specified by 'offset' with
 * the value of 'value'.
 * Can be used to patch the return address of malware to execute the
 * host program.
 *
 * @var MalelfBinary -- parasite/host object
 * @var _u32 -- offset to patch
 * @var unsigned -- value to patch
 */
_u32 malelf_patch_at(MalelfBinary *bin,
                           _u32 offset,
                           unsigned value)
{
        _u8* bin_data = bin->mem;

        if (offset < (unsigned) bin->size) {
                *(unsigned *)&bin_data[offset] = value;
        } else {
                MALELF_DEBUG_ERROR("Invalid offset in binary to patch. "
                                   "Offset is out of binary size.\n");
                return MALELF_EINV_OFFSET_ENTRY;
        }

        return MALELF_SUCCESS;
}

/**
 * Find the magic byte 'magic_bytes' in binary and patch with
 * value_addr.
 *
 * @var MalelfBinary -- parasite/host binary
 * @var unsigned long int -- magic_bytes
 * @var unsigned -- value_addr
 */
_u32 malelf_patch_at_magic_byte(MalelfBinary *binary,
                                _u32 magic_bytes,
                                _u32 value_addr)
{
        _u32 error;
        _u32 offset_magic_bytes = 0;
        union malelf_dword magic_addr;

        if (magic_bytes == 0) {
                magic_addr.long_val = MALELF_MAGIC_BYTES;
        } else {
                magic_addr.long_val = magic_bytes;
        }

        error = malelf_find_magic_number(binary->mem,
                                         binary->size,
                                         magic_addr,
                                         &offset_magic_bytes);

        if (MALELF_SUCCESS != error) {
                MALELF_DEBUG_ERROR("Failed to find magic bytes in "
                                   "binary...");
                return MALELF_EMISSING_MAGIC_BYTES;
        }

        return malelf_patch_at(binary,
                                      offset_magic_bytes,
                                      value_addr);
}
