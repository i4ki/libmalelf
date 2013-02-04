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

#include <malelf/ehdr.h>
#include <malelf/phdr.h>
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

_u32 malelf_report_ehdr(MalelfReport *report, MalelfBinary *bin)
{
        _i32 error = 0;
        MalelfEhdr ehdr;

        assert(NULL != bin);
        assert(NULL != report);
        assert(NULL != report->writer);

        malelf_binary_get_ehdr(bin, &ehdr);

        error = xmlTextWriterStartElement(report->writer, (const xmlChar *)"MalelfEhdr");

        MalelfEhdrType me_type;
        malelf_ehdr_get_type(&ehdr, &me_type);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"type", 
                                                "%d", me_type.value);

        MalelfEhdrMachine me_machine;
        malelf_ehdr_get_machine(&ehdr, &me_machine);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"machine", 
                                                "%d", me_machine.value);


        MalelfEhdrVersion me_version;
        malelf_ehdr_get_version(&ehdr, &me_version);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"version", 
                                                "%d", me_version.value);

        _u32 entry;
        malelf_ehdr_get_entry(&ehdr, &entry);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"entry", 
                                               "0x%08x", entry);

        _u32 phoff;
        malelf_ehdr_get_phoff(&ehdr, &phoff);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"phoff", 
                                                "0x%08x", phoff);
        
        _u32 shoff;
        malelf_ehdr_get_shoff(&ehdr, &shoff);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"shoff", 
                                                "0x%08x", shoff);
        
        _u32 flags;
        malelf_ehdr_get_flags(&ehdr, &flags);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"flags", 
                                                "%d", flags);

        _u32 phentsize;
        malelf_ehdr_get_phentsize(&ehdr, &phentsize);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"phentsize", 
                                                "%d", phentsize);

        _u32 phnum;
        malelf_ehdr_get_phnum(&ehdr, &phnum);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"phnum", 
                                                "%d", phnum);

        _u32 shentsize;
        malelf_ehdr_get_shentsize(&ehdr, &shentsize);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"shentsize", 
                                                "%d", shentsize);

        _u32 shnum;
        malelf_ehdr_get_shnum(&ehdr, &shnum);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"shnum", 
                                                "%d",  shnum);

        _u32 shstrndx;
        malelf_ehdr_get_shstrndx(&ehdr, &shstrndx);        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"shstrndx", 
                                                "%d", shstrndx);

        if (-1 == error) {
                return MALELF_ERROR;
        }

        xmlTextWriterEndElement(report->writer);

        return MALELF_SUCCESS;
}

static _u32 _malelf_report_phdr(MalelfReport *report, 
                                MalelfBinary *bin, 
                                _u32 index)
{ 
        Elf32_Phdr *phdr;
        MalelfPhdr me_phdr;
        _i32 error;

        assert(NULL != bin);
        assert(NULL != report);
        assert(NULL != report->writer);

        malelf_binary_get_phdr(bin, &me_phdr);

        phdr = me_phdr.uhdr.h32 + index;

        error = xmlTextWriterStartElement(report->writer, 
                                          (const xmlChar *)"MalelfPhdr");
        
        error = xmlTextWriterWriteFormatElement(report->writer, 
                                                (const xmlChar *)"type", 
                                                "%d", phdr->p_type);
        
        if (-1 == error) {
                return MALELF_ERROR;
        }
        xmlTextWriterEndElement(report->writer);
        return MALELF_SUCCESS;
}

_u32 malelf_report_phdr(MalelfReport *report, MalelfBinary *bin)
{
        _i32 error = 0;
        _u32 phnum;
        MalelfPhdr phdr;
        MalelfEhdr ehdr;
        _u32 i;

        UNUSED(phdr);
        UNUSED(report);
        UNUSED(error);

        assert(NULL != bin);
        assert(NULL != report);
        assert(NULL != report->writer);

        malelf_binary_get_phdr(bin, &phdr);
        malelf_binary_get_ehdr(bin, &ehdr);
        malelf_ehdr_get_phnum(&ehdr, &phnum);

        printf("%d\n", phnum);
        for (i = 0; i < phnum; i++) {
                _malelf_report_phdr(report, bin, i); 
        }
       
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

