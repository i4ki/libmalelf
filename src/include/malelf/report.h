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

/*!
 *
 */
typedef enum {
        MALELF_OUTPUT_XML,
        MALELF_OUTPUT_TEXT
} MalelfOutputFormat;


/*!
 *
 */
typedef struct {
        char *fname;
        xmlTextWriterPtr writer;
        _u8 format;
} MalelfReport;


/*!
 *
 */
_u32 malelf_report_open(MalelfReport *report, const char *fname, _u8 format);


/*!
 *
 */
_u32 malelf_report_ehdr(MalelfReport *report, MalelfBinary *bin);


/*!
 *
 */
_u32 malelf_report_phdr(MalelfReport *report, MalelfBinary *bin);

/*!
 *
 */
_u32 malelf_report_shdr(MalelfReport *report, MalelfShdr *shdr);


/*!
 *
 */
_u32 malelf_report_binary(MalelfReport *report, MalelfBinary *binary);

_u32 malelf_report_close(MalelfReport *report);


MALELF_END_DECLS


#endif /* MALELF_REPORT_H */
