#ifndef __IASP_MESSAGE_H__
#define __IASP_MESSAGE_H__


typedef enum {
    IASP_HMSG_INIT_HELLO = 1,
    IASP_HMSG_RESP_HELLO = 2,
    IASP_HMSG_INIT_AUTH = 3,
    IASP_HMSG_RESP_AUTH = 4,
    IASP_HMSG_REDIRECT = 5,
    IASP_HMSG_SESSION_AUTH = 6,
    IASP_HMSG_HINT_REQ = 7,
    IASP_HMSG_HINT_RESP = 8,
} iasp_handshake_msg_code_t;


#endif
