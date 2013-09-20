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
#include <string.h>
#include <stdbool.h>

#include <malelf/table.h>
#include <malelf/error.h>

_u32 malelf_table_add_int_value(MalelfTable *obj, int value)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (obj->element < (obj->nrows * obj->ncolumns)) {
                sprintf(obj->content[obj->element], "%d", value);
                obj->element++;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_table_add_hex_value(MalelfTable *obj, int value)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (obj->element < (obj->nrows * obj->ncolumns)) {
                sprintf(obj->content[obj->element], "0x%08x", value);
                obj->element++;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_table_add_str_value(MalelfTable *obj, const char *value)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if ((NULL == value) ||
            (strlen(value) > MALELF_TABLE_CONTENT_LEN)) {
                return MALELF_ERROR;
        }

        if (obj->element < (obj->nrows * obj->ncolumns)) {
                strncpy(obj->content[obj->element], value, strlen(value));
                obj->element++;
        }

        return MALELF_SUCCESS;
}


_u32 malelf_table_add_row(MalelfTable *obj, char **row)
{
        unsigned int i;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == row) {
                return MALELF_ERROR;
        }

        for (i = 0; i < obj->ncolumns; i++) {
                if (obj->element < (obj->nrows * obj->ncolumns)) {
                        strncpy(obj->content[obj->element],
                                row[i],
                                strlen(row[i]));
                        obj->element++;
                }
        }

        return MALELF_SUCCESS;
}

_u32 malelf_table_finish(MalelfTable *obj)
{
        unsigned int i;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL != obj->column_array) {
                free(obj->column_array);
        }

        if (NULL != obj->column_position) {
                free(obj->column_position);
        }

        for (i = 0; i < obj->nrows * obj->ncolumns; i++) {
                if (NULL != obj->content[i]) {
                        free(obj->content[i]);
                }
        }

        free(obj->content);

        return MALELF_SUCCESS;
}

static _u32 _malelf_table_alloc(MalelfTable *obj)
{
        unsigned int i;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        obj->content = (char**) malloc((obj->nrows * obj->ncolumns)
                                       * sizeof(char *));
        if (NULL == obj->content) {
                fprintf(stderr, "out of memory\n");
                return MALELF_ERROR;
        }

        for (i = 0; i < obj->nrows * obj->ncolumns; i++) {
                obj->content[i] = (char*)malloc(50*sizeof(char));
                if (obj->content[i] == NULL) {
                        fprintf(stderr, "out of memory\n");
                        return MALELF_ERROR;
                }
                memset(obj->content[i], 0, 50);
        }
        return MALELF_SUCCESS;
}

static _u32 _malelf_table_alloc_column_array(MalelfTable *obj)
{
        unsigned int i = 0;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        obj->column_array = (int *)malloc(sizeof(int)*obj->ncolumns);
        obj->column_position = (int *)malloc(sizeof(int)*obj->ncolumns);
        for (i = 0; i < (obj->ncolumns); i++) {
                obj->column_array[i] = 0;
                obj->column_position[i] = 0;
        }

        return MALELF_SUCCESS;
}

_u32 malelf_table_init(MalelfTable *obj,
                            unsigned int width,
                            unsigned int nrows,
                            unsigned int ncolumns)
{
        if (NULL == obj) {
                fprintf(stdout, "[INIT] MalelfTable object is NULL!\n");
                return MALELF_ERROR;
        }

        if ((0 == width) || (80 < width)) {
                fprintf(stdout, "[INIT] Invalid WIDTH value!\n");
                return MALELF_ERROR;
        }

        if (0 == nrows) {
                fprintf(stdout, "[INIT] Invalid Number of ROWS!\n");
                return MALELF_ERROR;
        }

        if (0 == ncolumns) {
                fprintf(stdout, "[INIT] Invalid Number of COLUMNS!\n");
                return MALELF_ERROR;
        }

        if (0 != (width % ncolumns)) {
                fprintf(stdout, "[INIT] WIDTH mod COLUMNS MUST be 0!\n");
                return MALELF_ERROR;
        }

        obj->width = width;
        obj->nrows = nrows;
        obj->ncolumns = ncolumns;
        obj->line.flag = false;
        obj->line.end = PLUS;
        obj->line.begin = PLUS;
        obj->line.middle = LESS;
        obj->line.partition = PLUS;
        obj->title = NULL;
        obj->headers = NULL;
        obj->content = NULL;
        obj->element = 0;
        obj->pos = 0;

        _malelf_table_alloc(obj);
        _malelf_table_alloc_column_array(obj);

        return MALELF_SUCCESS;
}



_u32 malelf_table_set_title(MalelfTable *obj, char *title)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == title) {
                return MALELF_ERROR;
        }

        obj->title = title;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_headers(MalelfTable *obj, char **headers)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == headers) {
                return MALELF_ERROR;
        }

        obj->headers = headers;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_content(MalelfTable *obj, char **content)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == content) {
                return MALELF_ERROR;
        }

        obj->content = content;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_width(MalelfTable *obj, unsigned int width)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->width = width;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_nrows(MalelfTable *obj, unsigned int nrows)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->nrows = nrows;

        return MALELF_SUCCESS;
}

_u32 malelf_table_set_ncolumns(MalelfTable *obj, unsigned int ncolumns)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        obj->ncolumns = ncolumns;

        return MALELF_SUCCESS;
}

static void _malelf_table_print_char(char character)
{
        fprintf(stdout, "%c", character);
}

static void _malelf_table_print_str(char *str)
{
        fprintf(stdout, "%s", str);
}

static void _malelf_table_new_line()
{
        fprintf(stdout, "\n");
}

static _u32 _malelf_table_print_line(MalelfTable *obj)
{
        unsigned int i;
        unsigned int array_pos = 0;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        _malelf_table_print_char(obj->line.begin);
        for (i = 1; i < obj->width; i++) {
                if (((unsigned int)obj->column_position[array_pos] == i) &&
                    (true == obj->line.flag)) {
                        _malelf_table_print_char(obj->line.partition);
                        array_pos++;
                } else {
                        _malelf_table_print_char(obj->line.middle);
                }
        }
        _malelf_table_print_char(obj->line.end);
        _malelf_table_new_line();

        return MALELF_SUCCESS;
}

static int _malelf_table_get_column_middle(unsigned int colx,
                                           unsigned int coly,
                                           char *str)
{
        if (NULL == str || 0 == strlen(str)) {
                return -1;
        }
        return ((colx + coly)/2) - (strlen(str)/2);
}


static _u32 _malelf_table_print_title(MalelfTable *obj)
{
        unsigned int i;
        unsigned int middle;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->title) {
                return MALELF_ERROR;
        }

        middle = _malelf_table_get_column_middle(0, obj->width, obj->title);
        _malelf_table_print_line(obj);
        _malelf_table_print_char(PIPE);
        for (i = 1; i < obj->width; i++) {
                _malelf_table_print_char(EMPTY);
                if (middle == i) {
                        fprintf(stdout, "%s", obj->title);
                        i = i + strlen(obj->title);
                }
        }
        _malelf_table_print_char(PIPE);
        _malelf_table_new_line();
        obj->line.flag = true;
        _malelf_table_print_line(obj);

        return MALELF_SUCCESS;
}

static _u32 _malelf_table_print_headers(MalelfTable *obj)
{
        unsigned int i;
        unsigned int col_middle;
        unsigned int pos = 0;
        unsigned int col = 0;
        static unsigned int count = 2;
        unsigned int column = 1;
        unsigned int old_column = 0;


        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->title) {
                _malelf_table_print_line(obj);
        }

        col_middle = _malelf_table_get_column_middle(old_column,
                                                     obj->column_position[old_column],
                                                     obj->headers[pos]);

        _malelf_table_print_char(PIPE);
        for (i = 1; i < obj->width; i++) {
                if (i == col_middle) {
                        _malelf_table_print_str(obj->headers[pos]);
                        i = i + strlen(obj->headers[pos]) - 1;
                        pos++;
                        col_middle = _malelf_table_get_column_middle(obj->column_position[old_column],
                                                                     obj->column_position[column],
                                                                     obj->headers[pos]);
                        old_column = column;
                        column++;
                        count++;
                        continue;
                }
                if (i == (unsigned int)obj->column_position[col]) {
                        col++;
                        _malelf_table_print_char(PIPE);
                        continue;
                }
                _malelf_table_print_char(EMPTY);
        }
        _malelf_table_print_char(PIPE);
        _malelf_table_new_line();
        _malelf_table_print_line(obj);
        count = 2;

        return MALELF_SUCCESS;
}


static _u32 _malelf_table_print_content(MalelfTable *obj)
{
        unsigned int i;
        unsigned int col_middle;
        static unsigned int count = 2;
        unsigned int col = 0;
        unsigned int column = 1;
        unsigned int old_column = 0;

        if (NULL == obj) {
                return MALELF_ERROR;
        }
        col_middle = _malelf_table_get_column_middle(old_column,
                                                     obj->column_position[old_column],
                                                     obj->content[obj->pos]);
        _malelf_table_print_char(PIPE);
        for (i = 1; i < obj->width; i++) {
                if (i == col_middle) {
                        _malelf_table_print_str(obj->content[obj->pos]);
                        i = i + strlen(obj->content[obj->pos]) - 1;
                        obj->pos++;
                        if (obj->pos < obj->ncolumns*obj->nrows) {
                                col_middle = _malelf_table_get_column_middle(obj->column_position[old_column],
                                                                             obj->column_position[column],
                                                                             obj->content[obj->pos]);
                        }
                        old_column = column;
                        column++;
                        count++;
                        continue;
                }
                if (i == (unsigned int)obj->column_position[col]) {
                        col++;
                        _malelf_table_print_char(PIPE);
                        continue;
                }
                _malelf_table_print_char(EMPTY);
        }
        _malelf_table_print_char(PIPE);
        _malelf_table_new_line();
        if (obj->pos < obj->nrows*obj->ncolumns) {
                col_middle = _malelf_table_get_column_middle(obj->column_position[old_column],
                                                             obj->column_position[column],
                                                             obj->content[obj->pos]);
        }
        count = 2;

        return MALELF_SUCCESS;
}

static _u32 _malelf_table_column_length(MalelfTable *obj)
{
        unsigned int count = 0;
        unsigned int i = 0;
        unsigned int sum = 0;
        unsigned int rest = 0;
        unsigned int mod = 0;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        for (i = 0; i < obj->ncolumns; i++) {
                obj->column_array[i] = strlen(obj->headers[i]) + 2;
        }

        for (i = 0; i < (obj->ncolumns*obj->nrows); i++) {
                if ((int)(strlen(obj->content[i]) + 2) >
                    (int)obj->column_array[i % obj->ncolumns]) {
                        obj->column_array[i % obj->ncolumns] = strlen(obj->content[i]) + 2;
                }
        }

        for (i = 0; i < obj->ncolumns; i++) {
                sum = sum + obj->column_array[i % obj->ncolumns];
        }

        if (sum > obj->width) {
                return MALELF_ERROR;
        } else {
                rest = obj->width - sum;
                if (rest < obj->ncolumns) {
                        obj->column_array[0] += rest;
                } else {
                        mod = rest % obj->ncolumns;
                        rest = rest/obj->ncolumns;
                        for (i = 0; i < obj->ncolumns; i++) {
                                obj->column_array[i] += rest;
                        }
                        obj->column_array[0] += mod;
                }
        }

        for (i = 0; i < obj->ncolumns; i++) {
                count += obj->column_array[i];
                obj->column_position[i] = count;
        }

        return MALELF_SUCCESS;
}


_u32 malelf_table_print(MalelfTable *obj)
{
        unsigned int j;

        if (MALELF_SUCCESS != _malelf_table_column_length(obj)) {
                return MALELF_ERROR;
        }

        if (NULL != obj->title) {
                _malelf_table_print_title(obj);
        }

        if (NULL != obj->headers) {
                _malelf_table_print_headers(obj);
        } else {
                if (NULL == obj->title) {
                        _malelf_table_print_line(obj);
                }
        }

        for (j = 0; j < obj->nrows; j++) {
                _malelf_table_print_content(obj);
        }

        _malelf_table_print_line(obj);
        _malelf_table_new_line();

        return MALELF_SUCCESS;
}
