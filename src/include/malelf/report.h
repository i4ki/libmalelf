/* 
 * The malelf library was written in pure C, with the objective to 
 * provide a quick and easy way a set functions for programmers to 
 * manipulate ELF files. With libmalelf can dissect and infect ELF 
 * files. Evil using this library is the responsibility of the programmer.
 *
 * Author: Tiago Natel de Moura <tiago4orion@gmail.com>
 *
 * Contributor: Daniel Ricardo dos Santos <danielricardo.santos@gmail.com>
 *              Paulo Leonardo Benatto <benatto@gmail.com>
 *
 * Copyright 2012, 2013 by Tiago Natel de Moura. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef MALELF_REPORT_H
#define MALELF_REPORT_H

#include <elf.h>
#include <libxml/xmlwriter.h>

#include "types.h"
#include "ehdr.h"
#include "phdr.h"
#include "shdr.h"
#include "binary.h"

MALELF_BEGIN_DECLS

typedef enum {
        MALELF_OUTPUT_XML,
        MALELF_OUTPUT_TEXT
} MalelfOutputFormat;

typedef struct {
        char *fname;
        xmlTextWriterPtr writer;
        _u8 format;
} MalelfReport;


/*! Initialize report.
 *
 * \param report A valid MalelfReport object.
 * \param fname The file name to store the content.
 * \param format The type of output (XML or TEXT). 
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_open(MalelfReport *report, const char *fname, _u8 format);


/*! Create report of Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param bin A valid MalelfBinary object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr(MalelfReport *report, MalelfBinary *bin);


/*! Generate e_type report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_type(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_machine report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_machine(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_version report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_version(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_entry report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_entry(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_phoff report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_phoff(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_shoff report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_shoff(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_flags report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_flags(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_phentsize report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_phentsize(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_phnum report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_phnum(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_shentsize report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_shentsize(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_shnum report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_shnum(MalelfReport *report, MalelfEhdr *ehdr);


/*! Generate e_shstrndx report from Ehdr.
 *
 * \param report A valid MalelfReport object.
 * \param ehdr A valid MalelfEhdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_ehdr_shstrndx(MalelfReport *report, MalelfEhdr *ehdr);


/*! Create report of Phdr.
 *
 * \param report A valid MalelfReport object.
 * \param shdr A valid MalelfShdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_phdr(MalelfReport *report, MalelfBinary *bin);


/*! Create report of Shdr.
 *
 * \param report A valid MalelfReport object.
 * \param shdr A valid MalelfShdr object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_shdr(MalelfReport *report, MalelfBinary *bin);


/*! Create report of Ehdr, Phdr and Shdr.
 *
 * \param report A valid MalelfReport object.
 * \param bin A valid MalelfBinary object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_binary(MalelfReport *report, MalelfBinary *bin);


/*! Ends MalelfReport object.
 *
 * \report A valid MalelfReport object.
 *
 * \return MALELF_SUCCESS if operation was successful,
 *          otherwise returns MALELF_ERROR. 
 */
_u32 malelf_report_close(MalelfReport *report);


MALELF_END_DECLS


#endif /* MALELF_REPORT_H */
