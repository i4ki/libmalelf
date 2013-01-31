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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <elf.h>

#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/defines.h>
#include <malelf/report.h>


static _u32 _malelf_report_open_xml(MalelfReport *report, const char *fname)
{
        _i32 error = 0;

        assert(NULL != report);

        report->writer =  xmlNewTextWriterFilename(fname, 0);
        if (NULL == report->writer) {
                return MALELF_ERROR;
        }
        
        error = xmlTextWriterStartDocument(report->writer, 
                                           NULL, 
                                           "UTF8", 
                                           NULL);
        if (-1 == error) {
                return MALELF_ERROR;
        }
        
        error = xmlTextWriterSetIndent(report->writer, 1);
        if (-1 == error) {
                return MALELF_ERROR;
        }
        
        error = xmlTextWriterStartElement(report->writer, 
                                          (const xmlChar *)"MalelfBinary");
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

/*
_u32 malelf_report_shdr(MalelfReport *report, MalelfShdr *shdr)
*/

_u32 malelf_report_ehdr(MalelfReport *report, MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != ehdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        error = xmlTextWriterStartElement(report->writer, (const xmlChar *)"MalelfEhdr");
        
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"type", "%d", 1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"machine", "%d", 1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"version", "%d", 1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"entry", "%d", 1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"phoff", "%d", 1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"shoff", "%d", 1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"flags", "%d", 1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"phentsize", "%d", 1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"phnum", "%d", 1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"shentsize", "%d", 1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"shnum", "%d",  1);
        error = xmlTextWriterWriteFormatElement(report->writer, (const xmlChar *)"shstrndx", "%d", 1);

        if (-1 == error) {
                return MALELF_ERROR;
        }

        xmlTextWriterEndElement(report->writer);

        return MALELF_SUCCESS;
}

_u32 malelf_report_phdr(MalelfReport *report, MalelfPhdr *phdr)
{
        UNUSED(phdr);
        UNUSED(report);

        assert(NULL != report);
        assert(NULL != report->writer);

        return MALELF_SUCCESS;
}

_u32 malelf_report_close(MalelfReport *report) 
{
        _i32 error;

        assert(NULL != report);
        assert(NULL != report->writer);

        error = xmlTextWriterEndElement(report->writer);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        error = xmlTextWriterEndDocument(report->writer);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        xmlFreeTextWriter(report->writer);
        return MALELF_SUCCESS;
}

_u32 malelf_report_open(MalelfReport *report, const char *fname, _u8 format)
{
        switch(format) {
        case MALELF_OUTPUT_XML: return _malelf_report_open_xml(report, fname);
        //case MALELF_OUTPUT_TEXT:
        default: return MALELF_ERROR;
        }
        return MALELF_SUCCESS;
}

