#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <malelf/table.h>
#include <malelf/error.h>

static _u32 _malelf_table_add_int_value(MalelfTable *obj, int value)
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

static _u32 _malelf_table_add_hex_value(MalelfTable *obj, int value)
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

static _u32 _malelf_table_add_str_value(MalelfTable *obj, char *value)
{
        if (NULL == obj) {
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

_u32 malelf_table_add_value(MalelfTable *obj, void *value, MalelfTableType type)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        switch(type) {
        case MALELF_TABLE_INT: _malelf_table_add_int_value(obj, (int)value);
                               break;
        case MALELF_TABLE_STR: _malelf_table_add_str_value(obj, (char*)value);
                               break;
        case MALELF_TABLE_HEX: _malelf_table_add_hex_value(obj, (int)value);
                               break;
        }        

        return MALELF_SUCCESS;
}


_u32 malelf_table_finish(MalelfTable *obj)
{
        unsigned int i;

        if (NULL == obj) {
                return MALELF_ERROR;
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

        obj->content = (char**)malloc((obj->nrows * obj->ncolumns) * sizeof(char *));
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
        }
        return MALELF_SUCCESS;
}

_u32 malelf_table_set_file(MalelfTable *obj, const char *filename)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == filename) {
                return MALELF_ERROR;
        }

        obj->filename = fopen(filename, "a+");
        if (NULL == obj->filename) {
                return MALELF_ERROR;
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
        obj->filename = stdout;

        _malelf_table_alloc(obj);

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

static _u32 _malelf_table_get_column_length(MalelfTable *obj,
                                                 unsigned int *clength)
{
        if (NULL == obj) {
                return MALELF_ERROR;
        }
        *clength = obj->width/obj->ncolumns;

        return MALELF_SUCCESS;
}

static void _malelf_table_print_char(MalelfTable *obj, char character)
{
        fprintf(obj->filename, "%c", character);
}

static void _malelf_table_print_str(MalelfTable *obj, char *str)
{
        fprintf(obj->filename, "%s", str);
}

static void _malelf_table_new_line(MalelfTable *obj)
{
        fprintf(obj->filename, "\n");
}

static _u32 _malelf_table_print_line(MalelfTable *obj)
{
        unsigned int i;
        unsigned int col_length;
        unsigned int aux;

         _malelf_table_get_column_length(obj, &col_length);
        aux = col_length;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        _malelf_table_print_char(obj, obj->line.begin);
        for (i = 1; i < obj->width; i++) {
                if ((aux == i) && (true == obj->line.flag)) {
                        _malelf_table_print_char(obj, obj->line.partition);
                        aux = aux + col_length;
                } else {
                        _malelf_table_print_char(obj, obj->line.middle);
                }
        }
        _malelf_table_print_char(obj, obj->line.end);
        _malelf_table_new_line(obj);

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
        _malelf_table_print_char(obj, PIPE);
        for (i = 1; i < obj->width; i++) {
                _malelf_table_print_char(obj, EMPTY);
                if (middle == i) {
                        fprintf(obj->filename, obj->title);
                        i = i + strlen(obj->title);
                }
        }
        _malelf_table_print_char(obj, PIPE);
        _malelf_table_new_line(obj);
        obj->line.flag = true;
        _malelf_table_print_line(obj);

        return MALELF_SUCCESS;
}

static _u32 _malelf_table_print_headers(MalelfTable *obj)
{
        unsigned int i;
        unsigned int col_length;
        unsigned int col_middle;
        unsigned int pos = 0;
        unsigned int col_begin = 0;
        unsigned int col_end = 0;
        static unsigned int count = 2;
        unsigned int partitions = 0;

        if (NULL == obj) {
                return MALELF_ERROR;
        }

        if (NULL == obj->title) {
                _malelf_table_print_line(obj);
        }

        _malelf_table_get_column_length(obj, &col_length);
        col_end = col_length;
        partitions = col_length;
        col_middle = _malelf_table_get_column_middle(col_begin,
                                                 col_end,
                                                 obj->headers[pos]);

        _malelf_table_print_char(obj, PIPE);
        for (i = 1; i < obj->width; i++) {
                if (i == col_middle) {
                        _malelf_table_print_str(obj, obj->headers[pos]);
                        i = i + strlen(obj->headers[pos]) - 1;
                        col_end = col_length * count;
                        col_begin = col_begin + col_length;
                        pos++;
                        col_middle = _malelf_table_get_column_middle(col_end,
                                                                 col_begin,
                                                                 obj->headers[pos]);
                        count++;
                        continue;
                }
                if (i == partitions) {
                        _malelf_table_print_char(obj, PIPE);
                        partitions = partitions + col_length;
                        continue;
                }
                _malelf_table_print_char(obj, EMPTY);
        }
        _malelf_table_print_char(obj, PIPE);
        _malelf_table_new_line(obj);
        _malelf_table_print_line(obj);

        return MALELF_SUCCESS;
}


static _u32 _malelf_table_print_content(MalelfTable *obj)
{
        unsigned int i;
        unsigned int col_length;
        unsigned int col_middle;
        static unsigned int pos = 0;
        unsigned int col_begin = 0;
        unsigned int col_end = 0;
        static unsigned int count = 2;
        unsigned int partitions = 0;


        if (NULL == obj) {
                return MALELF_ERROR;
        }

        _malelf_table_get_column_length(obj, &col_length);
        col_end = col_length;
        partitions = col_length;
        col_middle = _malelf_table_get_column_middle(col_begin,
                                                 col_end,
                                                 obj->content[pos]);
        _malelf_table_print_char(obj, PIPE);
        for (i = 1; i < obj->width; i++) {
                if (i == col_middle) {
                        _malelf_table_print_str(obj, obj->content[pos]);
                        i = i + strlen(obj->content[pos]) - 1;
                        col_end = col_length * count;
                        col_begin = col_begin + col_length;
                        pos++;
                        if (pos < obj->nrows*obj->ncolumns) {
                                col_middle = _malelf_table_get_column_middle(col_end,
                                                                         col_begin,
                                                                         obj->content[pos]);
                        }
                        count++;
                        continue;
                }
                if (i == partitions) {
                        _malelf_table_print_char(obj, PIPE);
                        partitions = partitions + col_length;
                        continue;
                }
                _malelf_table_print_char(obj, EMPTY);
        }
        _malelf_table_print_char(obj, PIPE);
        _malelf_table_new_line(obj);
        count = 2;
        col_begin = 0;
        col_end = partitions = col_length;
        if (pos < obj->nrows*obj->ncolumns) {
                col_middle = _malelf_table_get_column_middle(col_end,
                                                         col_begin,
                                                         obj->content[pos]);
        }

        return MALELF_SUCCESS;
}

_u32 malelf_table_print(MalelfTable *obj)
{
        unsigned int j;

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

        return MALELF_SUCCESS;
}
