/* 
 * The malelf library was written in pure C, with the objective to 
 * provide a quick and easy way a set functions for programmers to 
 * manipulate ELF files. With libmalelf can dissect and infect ELF 
 * files. Evil using this library is the responsibility of the programmer.
 *
 * Author: Paulo Leonardo Benatto <benatto@gmail.com>
 *
 * Contributor: Daniel Ricardo dos Santos <danielricardo.santos@gmail.com>
 *              Tiago Natel de Moura <tiago4orion@gmail.com>
 *
 * Copyright 2012, 2013 by Paulo Leonardo Benatto. All Rights Reserved.
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

#ifndef __MALELF_TABLE_H__
#define __MALELF_TABLE_H__

#include <stdbool.h>

#include "types.h"

#define PIPE  '|'
#define EMPTY ' '
#define PLUS  '+'
#define LESS  '-'

/* MalelfLine
 *
 * +-------------------------------------------------+
 * |  begin (+)        (+) partition (+)    end (+)  |
 * |         +----------+-------------+----------+   |
 * |                      middle (-)                 |
 * +-------------------------------------------------+
 *
 */

typedef enum {
        MALELF_TABLE_INT,
        MALELF_TABLE_HEX,
        MALELF_TABLE_STR
} MalelfTableType;

typedef struct {
        char begin;
        char middle;
        char end;
        char partition;
        bool flag;
} MalelfLine;

typedef struct {
        unsigned int width;
        unsigned int nrows;
        unsigned int ncolumns;
        unsigned int element;
        char *title;
        char **content;
        char **headers;
        unsigned int pos;
        MalelfLine line;
} MalelfTable;

/*! Initialize MalelfTable objetc. This method must be called.
 *
 *  \param obj a valid MalelfTable object.
 *  \param width The table width.
 *  \param nrows The numer of rows in a table.
 *  \param ncolumns The number of columns in ta table.
 *
 *  \return MALELF_SUCCESS if class was successfully initialized, 
 *          otherwise MALELF_ERROR.
 */
_u32 malelf_table_init(MalelfTable *obj,
                       unsigned int width,
                       unsigned int nrows,
                       unsigned int ncolumns);


/*!  Clean MalelfTable objetc. This method must be called.
 *
 *  \param obj a valid MalelfTable object.
 *
 *  \return MALELF_SUCCESS if class was successfully finished, 
 *          otherwise MALELF_ERROR.
 */
_u32 malelf_table_finish(MalelfTable *obj);


/*! Sets the title of the table.
 *  
 *  \param obj A valid MalelfTable object.
 *  \param title The table title.
 *
 *  \return MALELF_SUCCESS if title was successfully saved, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_table_set_title(MalelfTable *obj, char *title);


/*! Sets the headers of the table.
 *  
 *  \param obj A valid MalelfTable object.
 *  \param headers The table headers.
 *
 *  \return MALELF_SUCCESS if headers was successfully saved, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_table_set_headers(MalelfTable *obj, char **headers);


/*! Print the table.
 *  
 *  \param obj A valid MalelfTable object.
 *
 *  \return MALELF_SUCCESS if table was successfully printed, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_table_print(MalelfTable *obj);


/*! Add new value in a table.
 *  
 *  \param obj A valid MalelfTable object.
 *  \param value The value to be inserted.
 *  \param type The type of value.
 *
 *  \return MALELF_SUCCESS if the value was successfully inserted, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_table_add_value(MalelfTable *obj, 
                            void *value, 
                            MalelfTableType type);


/*! Add new row in a table.
 *  
 *  \param obj A valid MalelfTable object.
 *  \param row The row to be inserted.
 *
 *  \return MALELF_SUCCESS if the row was successfully inserted, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_table_add_row(MalelfTable *obj, char **row);


/*! Sets the table width.
 *  
 *  \param obj A valid MalelfTable object.
 *  \param width The new table width.
 *
 *  \return MALELF_SUCCESS if the width was successfullyly setted, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_table_set_width(MalelfTable *obj, unsigned int width);


/*! Sets the number of rows in a table.
 *  
 *  \param obj A valid MalelfTable object.
 *  \param nrows The number of rows.
 *
 *  \return MALELF_SUCCESS if the nrows was successfullyly setted, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_table_set_nrows(MalelfTable *obj, unsigned int nrows);


/*! Sets the number of rows in a table.
 *  
 *  \param obj A valid MalelfTable object.
 *  \param nrows The number of rows.
 *
 *  \return MALELF_SUCCESS if the nrows was successfullyly setted, 
 *          otherwise returns MALELF_ERROR.  
 */
_u32 malelf_table_set_ncolumns(MalelfTable *obj, unsigned int ncolumns);


#endif /* __MALELF_TABLE_H__ */
