#ifndef ERRORS_H__
#define ERRORS_H__

#define HLFL_NO_ERROR 0
#define HLFL_NO_ERROR_STR "success"

#define HLFL_UNKNOWN_OP 1
#define HLFL_UNKNOWN_OP_STR "Unknown operator"

#define HLFL_UNKNOWN_PROTOCOL 2
#define HLFL_UNKNOWN_PROTOCOL_STR "Unknown protocol"

#define HLFL_UNKNOWN_IP 3
#define HLFL_UNKNOWN_IP_STR "Bad IP address"

#define HLFL_NO_MIX_DIFF_LEN 4
#define HLFL_NO_MIX_DIFF_LEN_STR "'nomix' applied to lists of different lengths"

#define HLFL_DEFINE_SYNTAX_ERROR 5
#define HLFL_DEFINE_SYNTAX_ERROR_STR "Syntax error in the 'define' keyword"

#define HLFL_SYNTAX_ERROR 6
#define HLFL_SYNTAX_ERROR_STR "Syntax error"

#define HLFL_INCLUDE_FILE_NOT_FOUND 7
#define HLFL_INCLUDE_FILE_NOT_FOUND_STR "include : file not found"

#define HLFL_UNDEF_VAR_ERROR 8
#define HLFL_UNDEF_VAR_ERROR_STR "Undefined symbol"

#define HLFL_DEFINE_RECURSIVE 9
#define HLFL_DEFINE_RECURSIVE_STR "Recursive definition or too many elements in the definition"


#define HLFL_TOO_MANY_PROTOCOLS 10
#define HLFL_TOO_MANY_PROTOCOLS_STR "Too many protocols"
#endif
