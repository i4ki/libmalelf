/*
 * The libmalelf is an evil library that could be used for good! It was
 * developed with the intent to assist in the process of infecting
 * binaries and provide a safe way to analyze malwares.
 *
 * Evil using this library is the responsibility of the programmer.
 *
 * Author:
 *         Tiago Natel de Moura <natel@secplus.com.br>
 *
 * Contributors:
 *         Daniel Ricardo dos Santos <danielricardo.santos@gmail.com>
 *         Paulo Leonardo Benatto    <benatto@gmail.com>
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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
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


static _u32 _malelf_report_open_xml(MalelfReport *report,
                                    const char *fname)
{
        _i32 error = 0;

        assert(NULL != report);
        assert(NULL != fname);

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

_u32 malelf_report_start_element(MalelfReport *report,
                                 char *element_name)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != element_name);

        error = xmlTextWriterStartElement(report->writer,
                                          (const xmlChar *)element_name);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_end_element(MalelfReport *report)
{
        _i32 error = 0;
        assert(NULL != report);

        error = xmlTextWriterEndElement(report->writer);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_type(MalelfReport *report, MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        MalelfEhdrTable me_type;
        malelf_ehdr_get_type(ehdr, &me_type);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"type",
                                                "%d", me_type.value);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_machine(MalelfReport *report,
                                MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        MalelfEhdrTable me_machine;
        malelf_ehdr_get_machine(ehdr, &me_machine);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"machine",
                                                "%d", me_machine.value);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_version(MalelfReport *report,
                                MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        MalelfEhdrTable me_version;
        malelf_ehdr_get_version(ehdr, &me_version);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"version",
                                                "%d", me_version.value);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_entry(MalelfReport *report, MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        _u32 entry;
        malelf_ehdr_get_entry(ehdr, &entry);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"entry",
                                                "0x%08x", entry);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_phoff(MalelfReport *report, MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        _u32 phoff;
        malelf_ehdr_get_phoff(ehdr, &phoff);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"phoff",
                                                "0x%08x", phoff);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_shoff(MalelfReport *report, MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        _u32 shoff;
        malelf_ehdr_get_shoff(ehdr, &shoff);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"shoff",
                                                "0x%08x", shoff);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_flags(MalelfReport *report, MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        _u32 flags;
        malelf_ehdr_get_flags(ehdr, &flags);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"flags",
                                                "%d", flags);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_phentsize(MalelfReport *report, MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        _u32 phentsize;
        malelf_ehdr_get_phentsize(ehdr, &phentsize);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"phentsize",
                                                "%d", phentsize);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_phnum(MalelfReport *report, MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        _u32 phnum;
        malelf_ehdr_get_phnum(ehdr, &phnum);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"phnum",
                                                "%d", phnum);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_shentsize(MalelfReport *report, MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        _u32 shentsize;
        malelf_ehdr_get_shentsize(ehdr, &shentsize);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"shentsize",
                                                "%d", shentsize);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_shnum(MalelfReport *report,
                              MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        _u32 shnum;
        malelf_ehdr_get_shnum(ehdr, &shnum);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"shnum",
                                                "%d",  shnum);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr_shstrndx(MalelfReport *report,
                                 MalelfEhdr *ehdr)
{
        _i32 error = 0;
        assert(NULL != report);
        assert(NULL != report->writer);
        assert(NULL != ehdr);

        _u32 shstrndx;
        malelf_ehdr_get_shstrndx(ehdr, &shstrndx);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"shstrndx",
                                                "%d", shstrndx);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_ehdr(MalelfReport *report, MalelfBinary *bin)
{
        _i32 error = 0;
        MalelfEhdr ehdr;

        UNUSED(error);
        assert(NULL != bin);
        assert(NULL != report);
        assert(NULL != report->writer);

        malelf_binary_get_ehdr(bin, &ehdr);

        /* Start Element MalelfEhdr */
        malelf_report_start_element(report, "MalelfEhdr");
        malelf_report_ehdr_type(report, &ehdr);
        malelf_report_ehdr_machine(report, &ehdr);
        malelf_report_ehdr_version(report, &ehdr);
        malelf_report_ehdr_entry(report, &ehdr);
        malelf_report_ehdr_phoff(report, &ehdr);
        malelf_report_ehdr_shoff(report, &ehdr);
        malelf_report_ehdr_flags(report, &ehdr);
        malelf_report_ehdr_phentsize(report, &ehdr);
        malelf_report_ehdr_phnum(report, &ehdr);
        malelf_report_ehdr_shentsize(report, &ehdr);
        malelf_report_ehdr_shnum(report, &ehdr);
        malelf_report_ehdr_shstrndx(report, &ehdr);
        /* End Element MalelfEhdr */
        malelf_report_end_element(report);

        return MALELF_SUCCESS;
}


_u32 malelf_report_phdr_type(MalelfReport *report,
                             MalelfPhdr *phdr,
                             _u32 index)
{
        _i32 error;

        assert(NULL != phdr);
        assert(NULL != report);
        assert(NULL != report->writer);

         _u32 type;
        malelf_phdr_get_type(phdr, &type, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"type",
                                                "%d", type);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;

}

_u32 malelf_report_phdr_offset(MalelfReport *report,
                               MalelfPhdr *phdr,
                               _u32 index)
{
        _i32 error;

        assert(NULL != phdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 offset;
        malelf_phdr_get_offset(phdr, &offset, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"offset",
                                                "0x%08x", offset);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;

}

_u32 malelf_report_phdr_vaddr(MalelfReport *report,
                              MalelfPhdr *phdr,
                              _u32 index)
{
        _i32 error;

        assert(NULL != phdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 vaddr;
        malelf_phdr_get_vaddr(phdr, &vaddr, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"vaddr",
                                                "0x%08x", vaddr);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_phdr_paddr(MalelfReport *report,
                              MalelfPhdr *phdr,
                              _u32 index)
{
        _i32 error;

        assert(NULL != phdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 paddr;
        malelf_phdr_get_paddr(phdr, &paddr, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"paddr",
                                                "0x%08x", paddr);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_phdr_filesz(MalelfReport *report,
                               MalelfPhdr *phdr,
                               _u32 index)
{
        _i32 error;

        assert(NULL != phdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 filesz;
        malelf_phdr_get_filesz(phdr, &filesz, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"filesz",
                                                "%d", filesz);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_phdr_memsz(MalelfReport *report,
                              MalelfPhdr *phdr,
                              _u32 index)
{
        _i32 error;

        assert(NULL != phdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 memsz;
        malelf_phdr_get_memsz(phdr, &memsz, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"memsz",
                                                "%d", memsz);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_phdr_flags(MalelfReport *report,
                              MalelfPhdr *phdr,
                              _u32 index)
{
        _i32 error;

        assert(NULL != phdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 flags;
        malelf_phdr_get_flags(phdr, &flags, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"flags",
                                                "%d", flags);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_phdr_align(MalelfReport *report,
                              MalelfPhdr *phdr,
                              _u32 index)
{
        _i32 error;

        assert(NULL != phdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 align;
        malelf_phdr_get_align(phdr, &align, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"align",
                                                "%d", align);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_segment(MalelfReport *report,
                           MalelfBinary *bin,
                           _u32 index)
{
        MalelfPhdr phdr;
        _i32 error;

        UNUSED(error);
        assert(NULL != bin);
        assert(NULL != report);
        assert(NULL != report->writer);

        malelf_binary_get_phdr(bin, &phdr);

        /* End Element MalelfPhdr */
        malelf_report_start_element(report, "MalelfPhdr");

        malelf_report_phdr_type(report, &phdr, index);
        malelf_report_phdr_offset(report, &phdr, index);
        malelf_report_phdr_vaddr(report, &phdr, index);
        malelf_report_phdr_paddr(report, &phdr, index);
        malelf_report_phdr_filesz(report, &phdr, index);
        malelf_report_phdr_memsz(report, &phdr, index);
        malelf_report_phdr_flags(report, &phdr, index);
        malelf_report_phdr_align(report, &phdr, index);
        /* End Element MalelfEhdr */
        malelf_report_end_element(report);

        return MALELF_SUCCESS;
}

_u32 malelf_report_phdr(MalelfReport *report, MalelfBinary *bin)
{
        _u32 phnum;
        MalelfEhdr ehdr;
        _u32 i;

        assert(NULL != bin);
        assert(NULL != report);
        assert(NULL != report->writer);

        malelf_binary_get_ehdr(bin, &ehdr);
        malelf_ehdr_get_phnum(&ehdr, &phnum);

        for (i = 0; i < phnum; i++) {
                malelf_report_segment(report, bin, i);
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_shdr_name(MalelfReport *report,
                             MalelfShdr *shdr,
                             _u32 index)
{
        _i32 error;

        assert(NULL != shdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 name;
        malelf_shdr_get_name(shdr, &name, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"name",
                                                "%d", name);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_shdr_type(MalelfReport *report,
                             MalelfShdr *shdr,
                             _u32 index)
{
        _i32 error;

        assert(NULL != shdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 type;
        malelf_shdr_get_type(shdr, &type, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"type",
                                                "%d", type);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_shdr_flags(MalelfReport *report,
                              MalelfShdr *shdr,
                              _u32 index)
{
        _i32 error;

        assert(NULL != shdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 flags;
        malelf_shdr_get_flags(shdr, &flags, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"flags",
                                                "%d", flags);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_shdr_addr(MalelfReport *report,
                             MalelfShdr *shdr,
                             _u32 index)
{
        _i32 error;

        assert(NULL != shdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 addr;
        malelf_shdr_get_addr(shdr, &addr, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"addr",
                                                "0x%08x", addr);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_shdr_offset(MalelfReport *report,
                               MalelfShdr *shdr,
                               _u32 index)
{
        _i32 error;

        assert(NULL != shdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 offset;
        malelf_shdr_get_offset(shdr, &offset, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"offset",
                                                "0x%08x", offset);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_shdr_size(MalelfReport *report,
                             MalelfShdr *shdr,
                             _u32 index)
{
        _i32 error;

        assert(NULL != shdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 size;
        malelf_shdr_get_size(shdr, &size, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"size",
                                                "%d", size);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_shdr_link(MalelfReport *report,
                             MalelfShdr *shdr,
                             _u32 index)
{
        _i32 error;

        assert(NULL != shdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 link;
        malelf_shdr_get_size(shdr, &link, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"link",
                                                "%d", link);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_shdr_info(MalelfReport *report,
                             MalelfShdr *shdr,
                             _u32 index)
{
        _i32 error;

        assert(NULL != shdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 info;
        malelf_shdr_get_size(shdr, &info, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"info",
                                                "%d", info);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_shdr_addralign(MalelfReport *report,
                                  MalelfShdr *shdr,
                                  _u32 index)
{
        _i32 error;

        assert(NULL != shdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 addralign;
        malelf_shdr_get_size(shdr, &addralign, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"addralign",
                                                "%d", addralign);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_shdr_entsize(MalelfReport *report,
                                MalelfShdr *shdr,
                                _u32 index)
{
        _i32 error;

        assert(NULL != shdr);
        assert(NULL != report);
        assert(NULL != report->writer);

        _u32 entsize;
        malelf_shdr_get_size(shdr, &entsize, index);
        error = xmlTextWriterWriteFormatElement(report->writer,
                                                (const xmlChar *)"entsize",
                                                "%d", entsize);
        if (-1 == error) {
                return MALELF_ERROR;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_report_section(MalelfReport *report,
                           MalelfBinary *bin,
                           _u32 index)
{
        MalelfShdr shdr;
        _i32 error;

        UNUSED(error);
        assert(NULL != bin);
        assert(NULL != report);
        assert(NULL != report->writer);

        malelf_binary_get_shdr(bin, &shdr);

        malelf_report_start_element(report, "MalelfShdr");

        malelf_report_shdr_name(report, &shdr, index);
        malelf_report_shdr_type(report, &shdr, index);
        malelf_report_shdr_flags(report, &shdr, index);
        malelf_report_shdr_addr(report, &shdr, index);
        malelf_report_shdr_offset(report, &shdr, index);
        malelf_report_shdr_size(report, &shdr, index);
        malelf_report_shdr_link(report, &shdr, index);
        malelf_report_shdr_info(report, &shdr, index);
        malelf_report_shdr_addralign(report, &shdr, index);
        malelf_report_shdr_entsize(report, &shdr, index);
        malelf_report_end_element(report);

        return MALELF_SUCCESS;

}

_u32 malelf_report_shdr(MalelfReport *report,
                        MalelfBinary *bin)
{
        _u32 shnum;
        MalelfEhdr ehdr;
        _u32 i;

        assert(NULL != bin);
        assert(NULL != report);
        assert(NULL != report->writer);

        malelf_binary_get_ehdr(bin, &ehdr);
        malelf_ehdr_get_shnum(&ehdr, &shnum);

        for (i = 0; i < shnum; i++) {
                malelf_report_section(report, bin, i);
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
