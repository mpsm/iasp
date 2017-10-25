#ifndef __IASP_MESSAGE_H__
#define __IASP_MESSAGE_H__


typedef enum {
    INIT_HELLO = 1,
    RESP_HELLO = 2,
    INIT_AUTH = 3,
    RESP_AUTH = 4,
    REDIRECT = 5,
    SESSION_AUTH = 6,
    HINT_REQ = 7,
    HINT_RESP = 8,
} iasp_handshake_msg_code_t;


#endif
