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

#ifndef MALELF_SHDR_H
#define MALELF_SHDR_H

#include <elf.h>

#include "types.h"

MALELF_BEGIN_DECLS

#define MALELF_SHDR_SIZE(class) \
        ((class == MALELF_ELF32) ? sizeof (Elf32_Shdr) : sizeof (Elf64_Shdr))

/*!
 * \file phdr.h
 * \brief A class used to control the section header table.
 *
 * The MalelfShdr union is an opaque data type. It
 * should only be accessed via the following functions.
 *
 */

typedef struct {
        union {
                Elf32_Shdr *h32;    /*!< 32-bits ELF Section Headers */
                Elf64_Shdr *h64;    /*!< 64-bits ELF Section Headers */
        } uhdr;
        _u8 class;
} MalelfShdr;

typedef struct {
       char *name;
       _u16 type;
        _u32 addr;
       _u32 offset;
       _u32 size;
       MalelfShdr *shdr;
} MalelfSection;

typedef struct {
        char *name;
        _u32 value;
        char *description;
} MalelfShdrType;


/*! Get sh_name member from Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param name The sh_name saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if name was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_name(MalelfShdr *shdr, _u32 *name, _u32 index);


/*! Get sh_type member from Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param type The sh_type saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if type was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_type(MalelfShdr *shdr, _u32 *type, _u32 index);


/*! Get object MalelfShdrType.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param ms_type The MalelfShdrType saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if type was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_mstype(MalelfShdr *shdr,
                                   MalelfShdrType *ms_type,
                                   _u32 index);


/*! Get sh_flags member from Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param flags The sh_flags saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if flags was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_flags(MalelfShdr *shdr, _u32 *flags, _u32 index);


/*! Get sh_addr member from Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param addr The sh_addr saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if addr was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_addr(MalelfShdr *shdr, _u32 *addr, _u32 index);


/*! Get sh_offset member from Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param offset The sh_offset saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if offset was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_offset(MalelfShdr *shdr, _u32 *offset, _u32 index);


/*! Get sh_size member from Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param size The sh_size saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if size was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_size(MalelfShdr *shdr, _u32 *size, _u32 index);


/*! Get sh_link member from Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param link The sh_link saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if link was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_link(MalelfShdr *shdr, _u32 *link, _u32 index);


/*! Get sh_info member from Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param info The sh_info saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if info was successful set
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_info(MalelfShdr *shdr, _u32 *info, _u32 index);


/*! Get sh_addralign member from Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param addralign The sh_addralign saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if addralign was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_addralign(MalelfShdr *shdr,
                                      _u32 *addralign,
                                      _u32 index);


/*! Get sh_entsize member from Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param entsize The sh_entsize saved.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if entsize was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_get_entsize(MalelfShdr *shdr,
                                    _u32 *entsize,
                                    _u32 index);


/*! Set sh_name member on the Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param name The new name.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if name was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_set_name(MalelfShdr *shdr, _u32 name, _u32 index);


/*! Set sh_type member on the Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param type The new type.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if type was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_set_type(MalelfShdr *shdr, _u32 type, _u32 index);


/*! Set sh_flags member on the Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param flags The new flags.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if flags was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_set_flags(MalelfShdr *shdr, _u32 flags, _u32 index);


/*! Set sh_addr member on the Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param addr The new addr.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if addr was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_set_addr(MalelfShdr *shdr, _u32 addr, _u32 index);


/*! Set sh_offset member on the Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param offset The new offset.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if offset was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_set_offset(MalelfShdr *shdr, _u32 offset, _u32 index);


/*! Set sh_size member on the Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param size The new offset.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if offset was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_set_size(MalelfShdr *shdr, _u32 size, _u32 index);


/*! Set sh_link member on the Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param link The new link.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if link was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_set_link(MalelfShdr *shdr, _u32 link, _u32 index);


/*! Set sh_info member on the Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param info The new info.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if info was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_set_info(MalelfShdr *shdr, _u32 info, _u32 index);


/*! Set sh_addralign member on the Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param addralign The new addralign.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if addralign was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_set_addralign(MalelfShdr *shdr,
                                      _u32 addralign,
                                      _u32 index);


/*! Set sh_entsize member on the Section Header Table.
 *
 *  \param shdr A valid MalelfShdr object.
 *  \param entsize The new entsize.
 *  \param index The index of section.
 *
 *  \return MALELF_SUCCESS if entsize was successful set,
 *          otherwise returns MALELF_ERROR.
 */
extern _u32 malelf_shdr_set_entsize(MalelfShdr *shdr,
                                    _u32 entsize,
                                    _u32 index);


MALELF_END_DECLS


#endif /* MALELF_PHDR_H */
