/******************************************************************************
* Copyright (c) 2005, 2015  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html
*
* Contributors:
* Peter Dimitrov
* Gabor Szalai
* Kulcsár Endre
* Norbert Pinter
* Zoltan Medve
* Zsolt Nandor Torok
* Zsolt Török
******************************************************************************/
//
//  File:               SSHCLIENTasp_PT.hh
//  Description:        SSHCLIENTasp test port header
//  Rev:                R5A
//  Prodnr:             CNL 113 484
// 


#ifndef SSHCLIENTasp__PT_HH
#define SSHCLIENTasp__PT_HH

#include "SSHCLIENTasp_PortType.hh"
namespace SSHCLIENTasp__PortType {

typedef struct {
    boolean match;
    unsigned int start;
    unsigned int end;
} Regex_Prompt_MatchResult_SSH_client;

class Regex_Prompt_SSH_client {
    regex_t posix_regexp;
public:
    Regex_Prompt_SSH_client(const char *p_pattern, boolean raw_prompt = false);
    ~Regex_Prompt_SSH_client();
    Regex_Prompt_MatchResult_SSH_client match(const char *msg);
};

class Prompt_List_SSH_client {
    typedef struct {
    unsigned int id;
    boolean is_regex;
    union {
        char *prompt;
        Regex_Prompt_SSH_client *regex_prompt;
    };
    } prompt_elem;
    prompt_elem **elems;
    size_t n_elems;
    boolean id_to_index(unsigned int p_id, size_t &index) const;
public:
    Prompt_List_SSH_client() : elems(NULL), n_elems(0) { }
    ~Prompt_List_SSH_client();
    void set_prompt(unsigned int p_id, const char *p_prompt, boolean p_is_regex, boolean p_is_raw = false);
    void check(const char *warning_prefix);
    void clear();
    size_t nof_prompts() const { return n_elems; }
    int findPrompt(size_t &pos, const unsigned char *bufptr, size_t buflen) const;
};


class SSHCLIENTasp__PT : public SSHCLIENTasp__PT_BASE {
public:
    SSHCLIENTasp__PT(const char *par_port_name = NULL);
    ~SSHCLIENTasp__PT();

    void set_parameter(const char *parameter_name,
        const char *parameter_value);

    void Event_Handler(const fd_set *read_fds,
        const fd_set *write_fds, const fd_set *error_fds,
        double time_since_last_call);

protected:
    void user_map(const char *system_port);
    void user_unmap(const char *system_port);

    void user_start();
    void user_stop();

    void log(const char *fmt, ...)
           __attribute__((format(printf, 2, 3)));
    void error(const char *fmt, ...)
           __attribute__((format(printf, 2, 3)));
    void cleanup();
    void outgoing_send(const SSHCLIENTasp__Types::ASP__SSH& send_par);
    void outgoing_send(const SSHCLIENTasp__Types::ASP__SSH__SetPrompt& send_par);
    void outgoing_send(const SSHCLIENTasp__Types::ASP__SSH__SetRegexPrompt& send_par);
    void outgoing_send(const SSHCLIENTasp__Types::ASP__SSH__ClearPrompt& send_par);
    void outgoing_send(const SSHCLIENTasp__Types::ASP__SSH__SetMode& send_par);
    void outgoing_send(const SSHCLIENTasp__Types::ASP__SSH__Connect& send_par);
    void outgoing_send(const SSHCLIENTasp__Types::ASP__SSH__SetUserID& send_par);
    void outgoing_send(const SSHCLIENTasp__Types::ASP__SSH__SetRemoteHost& send_par);
    void outgoing_send(const SSHCLIENTasp__Types::ASP__SSH__SetRemotePort& send_par);
    void outgoing_send(const SSHCLIENTasp__Types::ASP__SSH__SetAdditionalParameters& send_par);
    int         isPrompt(size_t& pos);
    int         RecvMsg();
    void        log_buffer(const char * logmsg,
                    const unsigned char * buf, size_t buflen);
    boolean     buf_strcmp(const char * s1, const unsigned char * s2,
                size_t s2_len, size_t& pos);
    void        addPrompt(const char* parameter_name, const char* parameter_value);
    void        addRegexPrompt(const char* parameter_name, const char* parameter_value);

private:
    int fd_ssh;
    pid_t pid;

    //char recbuf[8192];

    int num_of_params_map;  // stores the number of additional parameters at the tim eof the mapping
                            // The unmap deletes any additoinal parameters are set via ASP
    int num_of_params;
    char **additional_parameters;
    /* The additional_parameters stores the parameters of the ssh
      index      meaning
      0         "ssh"
      1         ip_version
      2         userID
      3         remote_port
      4         remote_host
      ...       additional parameters
      last      NULL
    */
    CHARSTRING EOL;
    CHARSTRING LastSent;

    boolean assignEOL;
    int supressEcho;  // 0- no echo cancellation
                      // 1- try to cancel the echo by setting the terminal attributes
                      // 2- try to cancel the echo by sending "stty -echo" because the terminal settings are not working with every host
                      /*      How it works:
                                - After the first prompt is detected, th etest port send the "stty -echo" command
                                - The first prompt will be discaded
                                - The data until thenext prompt will be discarded as the printout of the stty command
                                - The test port waits for the next prompt, which will be handled normally
                      */
    boolean supressPrompt;
    boolean pseudoPrompt;
    boolean detectServerDisconnected;
    boolean debug;
    boolean statusOnSuccess;
    boolean emptyEcho;
    boolean suppressed;
    boolean rawPrompt;
    int  readmode;
    int prompt_seq;
    TTCN_Buffer ttcn_buf;
    fd_set readfds;
    Prompt_List_SSH_client prompt_list;
    
    char **add_params(int &num_of_par, char **params, const char *new_params);
};
}
#endif
