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
//  File:               SSHCLIENTasp_PT.cc
//  Description:        SSHCLIENTasp test port source
//  Rev:                R5A
//  Prodnr:             CNL 113 484
// 


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/wait.h>
#include <memory.h>

#define BUFFER_SIZE (100*1024)
#define BUFFERED    0
#define UNBUFFERED  1
#define RAW         2

#if defined LINUX || defined FREEBSD || defined WIN32
#include <pty.h>
#endif

#if defined SOLARIS || defined SOLARIS8
#include <strings.h>
#include <fcntl.h> 
#include <sys/ioctl.h> 
#include <sys/stream.h> 
#include <sys/stropts.h>
/////////////////////////////////////

int forkpty_solaris (int *amaster, char *name, struct termios
         *termp, struct winsize *winp)
{
    int fdm, fds;
    char *slavename;
    pid_t pid;
    fdm = open("/dev/ptmx", O_RDWR);  /* open master */
    grantpt(fdm);                     /* change permission of slave */
    unlockpt(fdm);                    /* unlock slave */
    slavename = ptsname(fdm);         /* get name of slave */
    if (name) strcpy(name, slavename);
    *amaster = fdm;
    if ((pid = fork()) < 0) {
    return pid;         /* error */
    }
    else if (pid != 0) {        /* parent */
    return pid;
    }
    else {            /* child */
    pid_t pgid;
    /* create a new session */
    pgid = setsid();
    if (pgid == -1) {
        perror("forkpty_solaris() setsid failed");
        return -1;
    }
    fds = open(slavename, O_RDWR);    /* open slave */
    ioctl(fds, I_PUSH, "ptem");       /* push ptem */
    ioctl(fds, I_PUSH, "ldterm");    /* push ldterm */
    dup2(fds, 0);
    dup2(fds, 1);
    dup2(fds, 2);
    ioctl(fds, TIOCSPGRP, &pgid);
    /* magic */
    if (termp)
        ioctl(fds, TCSETS, termp);
    if (winp)
        ioctl(fds, TIOCSWINSZ, winp);
    return pid;
    }
}
/////////////////////////////////////
#define forkpty forkpty_solaris
#endif

#include "SSHCLIENTasp_PT.hh"

////////////////////////////////////////////////////////////////
#if ( defined TTCN3_VERSION_MONOTONE ) && ! ( TTCN3_VERSION_MONOTONE <= 1100099)
#include "pattern.hh"
char* TTCN_pattern_to_regexp_sshclient(const char* patt){
  return TTCN_pattern_to_regexp(patt);
}
#else
#ifndef TTCN_pattern_to_regexp
extern char* TTCN_pattern_to_regexp(const char*,int);
char* TTCN_pattern_to_regexp_sshclient(const char* patt){
  return TTCN_pattern_to_regexp(patt,1);
}
#endif
#endif

using namespace SSHCLIENTasp__Types;
namespace SSHCLIENTasp__PortType {



SSHCLIENTasp__PT::SSHCLIENTasp__PT(const char *par_port_name)
    : SSHCLIENTasp__PT_BASE(par_port_name)
{
// setting defaults
    debug = FALSE;
    statusOnSuccess = FALSE;
    fd_ssh = -1;
    pid = -1;
    LastSent = "";
    assignEOL = TRUE;
    EOL = "\n";
    supressEcho = 0;
    supressPrompt = FALSE;
    pseudoPrompt = FALSE;
    emptyEcho = FALSE;
    suppressed = FALSE;
    rawPrompt = FALSE;
    readmode = BUFFERED;
    detectServerDisconnected = TRUE;
    FD_ZERO(&readfds);
    num_of_params=6;
    num_of_params_map=6;
    prompt_seq=0;
    additional_parameters = (char **)Malloc(6*sizeof(char*));
    additional_parameters[0]=mcopystr("ssh") ;
    additional_parameters[1]=mcopystr("-4") ; // ip_version
    additional_parameters[2]=mcopystr("-lroot") ; // userID
    additional_parameters[3]=mcopystr("-p22") ; // remote_port
    additional_parameters[4]=mcopystr("localhost") ; // remote_host
    additional_parameters[5]=NULL ; // NULL
    
}


SSHCLIENTasp__PT::~SSHCLIENTasp__PT()
{
    prompt_list.clear();
    cleanup();
    for(int a=0;a<num_of_params;a++) Free(additional_parameters[a]);
    Free(additional_parameters);
    additional_parameters=NULL;
}


void SSHCLIENTasp__PT::set_parameter(const char *parameter_name,
    const char *parameter_value)
{
    if(strcasecmp(parameter_name, "debug") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        if (strcasecmp(parameter_value,"yes") == 0)
            debug = TRUE;
        else if(strcasecmp(parameter_value,"no") == 0)
            debug = FALSE;
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. Only yes and no can be used!" , 
                parameter_value, parameter_name); 
    }
    else if(strcasecmp(parameter_name, "statusOnSuccess") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        if (strcasecmp(parameter_value,"yes") == 0)
            statusOnSuccess = TRUE;
        else if(strcasecmp(parameter_value,"no") == 0)
            statusOnSuccess = FALSE;
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. Only yes and no can be used!" , 
                parameter_value, parameter_name); 
    }
    else if(strcasecmp(parameter_name, "remote_host") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        Free(additional_parameters[4]); // remote_host
        additional_parameters[4]=mcopystr(parameter_value) ; // remote_host
    }
    else if(strcasecmp(parameter_name, "remote_port") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        Free(additional_parameters[3]); // remote_port
        additional_parameters[3]=mprintf("-p%s",parameter_value) ; // remote_port
    }
    else if(strcasecmp(parameter_name, "additional_parameters") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        additional_parameters=add_params(num_of_params,additional_parameters,parameter_value);
    }
    else if(strcasecmp(parameter_name, "ip_version") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        CHARSTRING ip_version = parameter_value;
        if(ip_version != "4" && ip_version != "6")
            error("set_parameter(): Invalid parameter value: %s for parameter %s. Valid values: 4 or 6!" , 
                parameter_value, parameter_name); 
        Free(additional_parameters[1]); // ip_version
        additional_parameters[1]=mprintf("-%s",parameter_value) ; // ip_version
    }
    else if(strcasecmp(parameter_name, "EOL") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        if (strcasecmp(parameter_value,"WINDOWS") == 0)
            EOL = "\r\n";
        else if (strcasecmp(parameter_value,"UNIX") == 0)
            EOL = "\n";
        else if (strcasecmp(parameter_value,"MAC") == 0)
            EOL = "\r";
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. Valid values: WINDOWS, UNIX, MAC!" , 
                parameter_value, parameter_name); 
    }
    else if(strcasecmp(parameter_name, "assignEOL") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        if (strcasecmp(parameter_value,"yes") == 0)
            assignEOL = TRUE;
        else if (strcasecmp(parameter_value,"no") == 0)
            assignEOL = FALSE;
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. Only yes and no can be used!" , 
                parameter_value, parameter_name); 
    }
    else if(strcasecmp(parameter_name, "supressEcho") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        if (strcasecmp(parameter_value,"yes") == 0)
            supressEcho = 1;
        else if (strcasecmp(parameter_value,"no") == 0)
            supressEcho = 0;
        else if (strcasecmp(parameter_value,"stty") == 0)
            supressEcho = 2;
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. Only \"yes\", \"no\" or \"stty\" can be used!" , 
                parameter_value, parameter_name); 
    } 
    else if(strcasecmp(parameter_name, "supressPrompt") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        if (strcasecmp(parameter_value,"yes") == 0)
            supressPrompt = TRUE;
        else if (strcasecmp(parameter_value,"no") == 0)
            supressPrompt = FALSE;
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. Only yes and no can be used!" , 
                parameter_value, parameter_name); 
    }
    else if(strcasecmp(parameter_name, "pseudoPrompt") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        if (strcasecmp(parameter_value,"yes") == 0)
            pseudoPrompt = TRUE;
        else if (strcasecmp(parameter_value,"no") == 0)
            pseudoPrompt = FALSE;
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. Only yes and no can be used!" , 
                parameter_value, parameter_name); 
    } 

    else if(strcasecmp(parameter_name, "READMODE") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        if (strcasecmp(parameter_value, "buffered") == 0) 
            readmode = BUFFERED;
        else if (strcasecmp(parameter_value, "unbuffered") == 0) 
            readmode = UNBUFFERED;
        else if (strcasecmp(parameter_value, "raw") == 0) 
            readmode = RAW;
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. Valid values: buffered, unbuffered, raw!" , 
                parameter_value, parameter_name); 
    }
    else if(strcasecmp(parameter_name, "detectServerDisconnected") == 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        if (strcasecmp(parameter_value, "yes") == 0)
            detectServerDisconnected = TRUE;
        else if (strcasecmp(parameter_value, "no") == 0)
            detectServerDisconnected = FALSE;
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. Only yes and no can be used!" , 
                parameter_value, parameter_name); 
    }
    else if(strncmp("prompt", parameter_name, 6) == 0)
    {
        if(strlen(parameter_name) < 7)
            error("set_parameter(): PROMPT parameters should be given as PROMPT<number> := \"value\".");
        errno = 0;
        size_t prompt_id = atoi(parameter_name + 6);
        if(errno)
            error("set_parameter(): error converting string \"%s\" in parameter name \"%s\" to number.", 
                parameter_name + 6, parameter_name);
        if(strlen(parameter_value) != 0)
        {
            log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
            prompt_list.set_prompt(prompt_id, parameter_value, FALSE);
        }
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. "
                    "PROMPT parameter must contain at least one character!", 
                    parameter_value, parameter_name);
    }

    else if(strncmp("regex_prompt", parameter_name, 12) == 0)
    {
        if(strlen(parameter_name) < 13) 
            error("set_parameter(): REGEX_PROMPT parameters should be given as REGEX_PROMPT<number> := \"value\".");
        errno = 0;
        size_t prompt_id = atoi(parameter_name + 12);
        if(errno) 
            error("set_parameter(): error converting string \"%s\" in parameter name \"%s\" to number.", 
                parameter_name + 12, parameter_name);
        if(strlen(parameter_value) != 0)
        {
            log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
            prompt_list.set_prompt(prompt_id, parameter_value, TRUE);
        } 
        else
            error("set_parameter(): Invalid parameter value: %s for parameter %s. "
                    "REGEX_PROMPT parameter must contain at least one character!", 
                    parameter_value, parameter_name);
    }

    else if(strncmp("raw_regex_prompt", parameter_name, 16) == 0) {
            if(strlen(parameter_name) < 17) 
                error("set_parameter(): RAW_REGEX_PROMPT parameters should be given as RAW_REGEX_PROMPT<number> := \"value\".");
            errno = 0;
            size_t prompt_id = atoi(parameter_name + 16);
            if(errno) 
                error("set_parameter(): error converting string \"%s\" in parameter name \"%s\" to number.", 
                    parameter_name + 16, parameter_name);
            if(strlen(parameter_value) != 0)
            {
                log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
                prompt_list.set_prompt(prompt_id, parameter_value, TRUE, TRUE);
                rawPrompt = TRUE;
            } 
            else {
                error("set_parameter(): Invalid parameter value: %s for parameter %s. "
                      "RAW_REGEX_PROMPT parameter must contain at least one character!", 
                        parameter_value, parameter_name);
                rawPrompt = FALSE;
           }
        }

    else if(strcmp("empty_echo", parameter_name) == 0){
      log("Reading testport parameter: %s = %s", parameter_name, parameter_value);
      if(strcmp(parameter_value, "yes") == 0){
        emptyEcho = TRUE;
      } 
      else {
        log("%s wasn't yes -> empty echo disabled.", parameter_value);   
      }
    }

    else
        TTCN_warning("%s: unknown & unhandled parameter: %s", get_name(), parameter_name);
}


void SSHCLIENTasp__PT::Event_Handler(const fd_set */*read_fds*/,
    const fd_set */*write_fds*/, const fd_set */*error_fds*/,
    double /*time_since_last_call*/)
{
    log("Calling Event_Handler().");
    if (RecvMsg() < 0)
    {
        if(detectServerDisconnected) return;
        else 
            error("Event handler(): Socket error or the server closed the connection!");
    }

    while(TRUE)
    {
        
        const unsigned char * bufptr = ttcn_buf.get_data();
        int prompt_len;
        boolean nl_found = FALSE, prompt_found = FALSE;
        size_t prompt_start_pos_prompt, prompt_start_pos_nl;

        log_buffer("Before password detection ttcn_buf contains:", ttcn_buf.get_data(), ttcn_buf.get_len());
        if(debug)
        {
            CHARSTRING tmpchr(ttcn_buf.get_len(), (const char*)ttcn_buf.get_data());
            TTCN_Logger::begin_event(TTCN_DEBUG);
            tmpchr.log();
            TTCN_Logger::end_event();
        }
	
        int length_of_login_text = ttcn_buf.get_len();
        log("Result of comparison: %d",((length_of_login_text >= 10) && (strncasecmp("Password: ", (const char*)bufptr+length_of_login_text-10,10) == 0)));
        if((length_of_login_text >= 10) && (strncasecmp("Password: ", (const char*)bufptr+length_of_login_text-10, 10) == 0))
        {
            suppressed = FALSE;
            incoming_message(CHARSTRING(ttcn_buf.get_len(), (const char*)bufptr));
            ttcn_buf.set_pos(length_of_login_text);
            ttcn_buf.cut();
       }
        if(readmode == RAW)
        {    
            suppressed = FALSE;
            incoming_message(CHARSTRING(ttcn_buf.get_len(), (const char*)bufptr));
            ttcn_buf.set_pos(ttcn_buf.get_len());
            ttcn_buf.cut();
            if(!ttcn_buf.get_len()) return;
        }
        else if (readmode == UNBUFFERED)
        {
            nl_found = buf_strcmp("\n", bufptr, ttcn_buf.get_len(),
                prompt_start_pos_nl);
            if ((prompt_len = isPrompt(prompt_start_pos_prompt))>=0)
                prompt_found = TRUE;
            

            //If there is neither new line nor prompt in the buffer then simply
            // return and wait for more data
            if(!nl_found && !prompt_found) return;
            else if((nl_found && !prompt_found) ||
                (nl_found && prompt_found && prompt_start_pos_nl <
                prompt_start_pos_prompt))
            {       // Process the lines before the prompt
                if(prompt_start_pos_nl) {
                    suppressed = FALSE;
                        if(prompt_seq !=1){
                          incoming_message(CHARSTRING(prompt_start_pos_nl,(const char*)bufptr));
                        } else {
                          log("stty response discarded");
                        }
                }
                ttcn_buf.set_pos(prompt_start_pos_nl+1);
                ttcn_buf.cut();
            }
            else 
            {
                //First send the data previous to the prompt ...
                if(prompt_start_pos_prompt)
                {
                    suppressed = FALSE;
                        if(prompt_seq !=1){
                          incoming_message(CHARSTRING(prompt_start_pos_prompt, (const char*)bufptr));
                        } else {
                          log("stty response discarded");
                        }
                    ttcn_buf.set_pos(prompt_start_pos_prompt);
                    ttcn_buf.cut();
                }
                //... and then send the prompt itself
                    bufptr = ttcn_buf.get_data();
                    if((supressEcho !=2) // do not use the stty command, 
                       || prompt_seq ){ // not the first prompt
                      if(!supressPrompt && !pseudoPrompt) {
                          suppressed = FALSE;
                          incoming_message(CHARSTRING(prompt_len, (const char*)bufptr));
                      }
                      else if(!supressPrompt) {
                          suppressed = FALSE;
                          incoming_message(ASP__SSH__PseudoPrompt(NULL_VALUE));
                      }
                      prompt_seq = 2;
                    } else {  // use stty & first prompt
                      prompt_seq = 1;
                      suppressed = FALSE;
                      LastSent = "stty -echo" + EOL;
                      log("Sending \"stty -echo\"");
                      if (write(fd_ssh, (const char*)LastSent, strlen((const char*)LastSent)) <0)
                      {
                          incoming_message(ASP__SSH__Status(INTEGER(2),CHARSTRING("Send error! Socket error!")));
                      }
                    }
                    ttcn_buf.set_pos(prompt_len);
                    ttcn_buf.cut();
            }
            nl_found = FALSE;
            prompt_found = FALSE;
            if(!ttcn_buf.get_len()) return;
        }
        else
        {
            // only send if the last line is prompt
            if ((prompt_len = isPrompt(prompt_start_pos_prompt))>=0)
            {
              log("Prompt start position: %zu", prompt_start_pos_prompt);
                // promptlen==0 is not checked here since it must contain
                // at least 1 character, that is checked in set_parameter()
                //First send the data previous to the prompt ...
                if(prompt_start_pos_prompt)
                {
                    int msg_end_pos = prompt_start_pos_prompt;
                    while(msg_end_pos>0)
                    {
                        if(bufptr[msg_end_pos-1]!='\n') break;
                        else msg_end_pos--;
                    }
                    if(msg_end_pos) {
                        suppressed = FALSE;
                        if(prompt_seq !=1){
                          incoming_message(CHARSTRING(msg_end_pos, (const char*)bufptr));
                        } else {
                          log("stty response discarded");
                        }
                    }
                    ttcn_buf.set_pos(prompt_start_pos_prompt);
                    ttcn_buf.cut();
                }

                if (emptyEcho && suppressed) {
                  suppressed = FALSE;
                  incoming_message("");
                }

                //... and then send the prompt itself
                bufptr = ttcn_buf.get_data();
                if((supressEcho !=2) // do not use the stty command, 
                   || prompt_seq ){ // not the first prompt
                  if(!supressPrompt && !pseudoPrompt) {
                      suppressed = FALSE;
                      incoming_message(CHARSTRING(prompt_len, (const char*)bufptr));
                  }
                  else if(!supressPrompt) {
                      suppressed = FALSE;
                      incoming_message(ASP__SSH__PseudoPrompt(NULL_VALUE));
                  }
                  prompt_seq = 2;
                } else {  // use stty & first prompt
                  prompt_seq = 1;
                  suppressed = FALSE;
                  LastSent = "stty -echo" + EOL;
                  log("Sending \"stty -echo\"");
                  if (write(fd_ssh, (const char*)LastSent, strlen((const char*)LastSent)) <0)
                  {
                      incoming_message(ASP__SSH__Status(INTEGER(2),CHARSTRING("Send error! Socket error!")));
                  }
                }

                ttcn_buf.set_pos(prompt_len);
                ttcn_buf.cut();
                
                if(!ttcn_buf.get_len()) return;
            }
            return;
        }
    }
    log("Leaving Event_Handler().");
}


void SSHCLIENTasp__PT::user_map(const char *system_port)
{
    log("Calling user_map(%s).",system_port);
    suppressed = FALSE;
    if(prompt_list.nof_prompts() == 0)
        error("Missing mandatory parameter: at least one PROMPT or REGEX_PROMPT parameter must be provided!");
    prompt_list.check(port_name);
    num_of_params_map=num_of_params;

    log("Leaving user_map().");
}


void SSHCLIENTasp__PT::user_unmap(const char *system_port)
{
    log("Calling user_unmap(%s).",system_port);
    cleanup();
    
    for(int i=(num_of_params_map-1);i<(num_of_params-1);i++){
      Free(additional_parameters[i]);
      additional_parameters[i]=NULL;
    }
    num_of_params=num_of_params_map;
    
    log("Leaving user_unmap().");
}


void SSHCLIENTasp__PT::cleanup()
{
    log("Calling cleanup().");
    FD_ZERO(&readfds);
    if(ttcn_buf.get_len()!=0)
    {
        TTCN_warning("(%s) cleanup(): Dropping partial message.", port_name);
        ttcn_buf.clear();
    }
    Uninstall_Handler();
    if (fd_ssh!=-1)
    {
        bool processRunning = true;
        int attemptToStop = 0;
        int changedStatePid;

        close(fd_ssh);
        fd_ssh = -1;
        
        while(processRunning) {
          switch(attemptToStop) {
          case 0:
            kill(pid, 0);
            break;
          case 1:
            kill(pid, SIGQUIT);
            break;
          case 2:
            kill(pid, SIGKILL);
            break;
          default:
            waitpid(-1, NULL, 0);
            log("Leaving cleanup().");
            return;
          }
          
          sleep(1);
          
          changedStatePid = waitpid(pid, NULL, WNOHANG);

          if (changedStatePid > 0) {
            log("Forked processed stopped.");
            processRunning = false;
          }
          else if (changedStatePid == 0) {
            attemptToStop++;
            log("(%s) cleanup(): Forked pseudo terminal with pid=%d could not be stopped, trying again.", port_name, (int)pid);
          }
          else if (changedStatePid < 0) {
            log("(%s) cleanup(): Error while waiting pid=%d to be stopped.", port_name, (int)pid);
            break;
          }
        }
    }
    log("Leaving cleanup().");
}


void SSHCLIENTasp__PT::user_start()
{
    log("Calling user_start().");
    log("Leaving user_start().");
}


void SSHCLIENTasp__PT::user_stop()
{
    log("Calling user_stop().");
    log("Leaving user_stop().");
}


void SSHCLIENTasp__PT::outgoing_send(const ASP__SSH& send_par)
{
    log("Calling outgoing_send (ASP_SSH).");
    if(fd_ssh == -1)
    {
        incoming_message(ASP__SSH__Status(INTEGER(1),CHARSTRING("ASP_SSH send error! No session!")));
        return;
    }
    LastSent = send_par;
    if (LastSent != EOL && assignEOL)        // assign EOL
        LastSent = LastSent + EOL;
    if (write(fd_ssh, (const char*)LastSent, strlen((const char*)LastSent)) <0)
    {
        incoming_message(ASP__SSH__Status(INTEGER(2),CHARSTRING("ASP_SSH send error! Socket error!")));
        return;
    }
    else if(statusOnSuccess) 
        incoming_message(ASP__SSH__Status(INTEGER(0),CHARSTRING("OK!")));
    LastSent = send_par;
    suppressed = TRUE;
    log("Leaving outgoing_send (ASP_SSH).");
}


void SSHCLIENTasp__PT::outgoing_send(const ASP__SSH__SetPrompt& send_par)
{
    log("Calling outgoing_send (ASP_SSH_SetPrompt).");
    addPrompt((const char*)send_par.prompt__name(), (const char*)send_par.prompt__value());
    log("Leaving outgoing_send (ASP_SSH_SetPrompt).");
}


void SSHCLIENTasp__PT::outgoing_send(const ASP__SSH__SetRegexPrompt& send_par)
{
    log("Calling outgoing_send (ASP_SSH_SetPrompt).");
    addRegexPrompt((const char*)send_par.prompt__name(), (const char*)send_par.prompt__value());
    log("Leaving outgoing_send (ASP_SSH_SetPrompt).");
}


void SSHCLIENTasp__PT::outgoing_send(const ASP__SSH__ClearPrompt& /*send_par*/)
{
    log("Calling outgoing_send (ASP_SSH_ClearPrompt).");
    prompt_list.clear();
    log("Leaving outgoing_send (ASP_SSH_ClearPrompt).");
}


void SSHCLIENTasp__PT::outgoing_send(const ASP__SSH__SetMode& send_par)
{
    log("Calling outgoing_send (ASP_SSH_SetMode).");
    readmode = (int) send_par.readmode();
    log("Leaving outgoing_send (ASP_SSH_SetMode).");
}


void SSHCLIENTasp__PT::outgoing_send(const ASP__SSH__Connect& /*send_par*/)
{
    log("Calling outgoing_send (ASP_SSH_Connect).");
    if(fd_ssh != -1)
    {
        incoming_message(ASP__SSH__Status(INTEGER(3),
        CHARSTRING("ASP_SSH_Connect send error! This ASP can only be used if the connection is closed!")));
        return;
    }
    char sSlave[80];
    pid = forkpty(&fd_ssh, sSlave, NULL , NULL );

    if (pid < 0)
    {
        error("outgoing_send (ASP_SSH_Connect): fork() failed!");
    } 
    else if (pid == 0)
    {   // child code
        int result=execvp("ssh",additional_parameters);       

        if(result < 0)
        {
            error("outgoing_send (ASP_SSH_Connect): execlp() failed!");
        }
        exit(0);
    }
    else 
    {
        // parent code
        // set echo handling
        if(supressEcho){
          log("(%s) Disable echo", port_name);
          struct termios tios;
          if(tcgetattr(fd_ssh, &tios)!=-1){
            tios.c_lflag &= ~(ECHO | ECHONL);
            if(tcsetattr(fd_ssh, TCSAFLUSH, &tios)==-1){
              TTCN_warning("(%s) Can not set the echo handling. tcsetattr() failed: %d, %s",port_name,errno,strerror(errno));
            }
          } else {
            TTCN_warning("(%s) Can not set the echo handling. tcgetattr() failed: %d, %s",port_name,errno,strerror(errno));
          }
        }
        if(statusOnSuccess) incoming_message(ASP__SSH__Status(INTEGER(0), CHARSTRING("OK!")));
        log("forkpty() returned. fd_ssh is set to %d", fd_ssh);
        log("(%s) outgoing_send (ASP_SSH_Connect): Parent: child started with pid=%d", port_name, (int)pid);
        FD_ZERO(&readfds);
        FD_SET(fd_ssh, &readfds);
        Install_Handler(&readfds, NULL, NULL, 0.0);
        //TTCN_Logger::begin_event(TTCN_DEBUG);
        //for(int i = 0; i<FD_SETSIZE; i++)
        //    if(FD_ISSET(i, &readfds)) TTCN_Logger::log_event("%d ", i);
        //TTCN_Logger::end_event();
        prompt_seq=0;
        log("Leaving outgoing_send (ASP_SSH_Connect) !");
    }
}


void SSHCLIENTasp__PT::outgoing_send(const ASP__SSH__SetUserID& send_par)
{
    log("Calling outgoing_send (ASP_SSH_SetUserID).");
    Free(additional_parameters[2]); // remote_port
    additional_parameters[2]=mprintf("-l%s",(const char*)send_par.usrid()) ; // remote_port
    log("Leaving outgoing_send (ASP_SSH_SetUserID).");
}


void SSHCLIENTasp__PT::outgoing_send(const ASP__SSH__SetRemoteHost& send_par)
{
    log("Calling outgoing_send (ASP_SSH_SetRemoteHost).");
    Free(additional_parameters[4]); // remote_host
    additional_parameters[4]=mcopystr((const char *)send_par.remotehost()) ; // remote_host
    log("Leaving outgoing_send (ASP_SSH_SetRemoteHost).");
}


void SSHCLIENTasp__PT::outgoing_send(const ASP__SSH__SetRemotePort& send_par)
{
    log("Calling outgoing_send (ASP_SSH_SetRemotePort).");
    Free(additional_parameters[3]); // remote_port
    additional_parameters[3]=mprintf("-p%s",(const char *)send_par.remoteport()) ; // remote_port
    log("Leaving outgoing_send (ASP_SSH_SetRemotePort).");
}


void SSHCLIENTasp__PT::outgoing_send(const ASP__SSH__SetAdditionalParameters& send_par)
{
    log("Calling outgoing_send (ASP_SSH_SetAdditionalParameters).");
    additional_parameters=add_params(num_of_params,additional_parameters,(const char*)send_par.additionalparameters());
    log("Leaving outgoing_send (ASP_SSH_SetAdditionalParameters).");
}


int SSHCLIENTasp__PT::RecvMsg()
{
    log("Calling RecvMsg().");
    unsigned char inbuf[BUFFER_SIZE];
    int end_len = BUFFER_SIZE;
    int len=read(fd_ssh, inbuf, end_len);

    log("New message received.");
    
    if (len < 1)
    {
        if(detectServerDisconnected)
        {
            log("Connection is broken. Send ASP_SSH_Connect again.");
            if(ttcn_buf.get_len()!=0)
            {
              ttcn_buf.clear();
            }
            cleanup();
            ASP__SSH__Close sshclose = NULL_VALUE;
            incoming_message(sshclose);
        }
        log("Leaving RecvMsg().");
        return -1;
    }
    
    for(int i=0;i<len;i++)
    {
        if(inbuf[i]!='\r' && inbuf[i]!='\0') ttcn_buf.put_c(inbuf[i]);
    }
 
    log_buffer("RecvMsg ttcn_buf message:", ttcn_buf.get_data(),
        ttcn_buf.get_len());
    if(debug)
    {
        CHARSTRING tmpchr(ttcn_buf.get_len(), (const char*)ttcn_buf.get_data());
        TTCN_Logger::begin_event(TTCN_DEBUG);
        tmpchr.log();
        TTCN_Logger::end_event();
    }
    log("Leaving RecvMsg().");
    return ttcn_buf.get_len();
}


// buf_strcmp compares the NULL-terminated string s1 to s2 of length s2_len 
// (s2 is not necessarily NULL-terminated). If s2 containes the substring s1, 
// then the function returns TRUE and pos is set to the starting position of s1 
// within s2, otherwise the return value is FALSE and pos remains unchanged.
boolean SSHCLIENTasp__PT::buf_strcmp(const char * s1, const unsigned char * s2, size_t s2_len, size_t& pos)
{
    size_t s1_len = strlen(s1);
    if(s1_len == 0) return FALSE;
    if(s1_len>s2_len) { return FALSE; }
    for(int i=0;i<(int)(s2_len-s1_len+1); )
    {
        size_t j = 0;
        while((unsigned char)s1[j] == s2[i+j])
        { 
            j++;
        }
        if(j==s1_len)
        { 
            pos = i;
            return TRUE;
        }
        i+=j>0?j:1;
    }
    return FALSE;
}


int SSHCLIENTasp__PT::isPrompt(size_t &pos)
{
    return prompt_list.findPrompt(pos, ttcn_buf.get_data(), ttcn_buf.get_len());
}


void SSHCLIENTasp__PT::addPrompt(const char* parameter_name, const char* parameter_value)
{
    if(strlen(parameter_name) < 7)
        error("addPrompt(): PROMPT parameters should be given as PROMPT<number> := \"value\".");
    errno = 0;
    size_t prompt_id = atoi(parameter_name + 6);
    if(errno)
        error("addPrompt(): error converting string \"%s\" in parameter name \"%s\" to number.", 
            parameter_name + 6, parameter_name);
    if(strlen(parameter_value) != 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        prompt_list.set_prompt(prompt_id, parameter_value, FALSE);
    }
    else
        error("addPrompt(): Invalid parameter value: %s for parameter %s. "
                "PROMPT parameter must contain at least one character!", 
                parameter_value, parameter_name);
}


void SSHCLIENTasp__PT::addRegexPrompt(const char* parameter_name, const char* parameter_value)
{
  if(!rawPrompt){
    if(strlen(parameter_name) < 13) 
        error("addRegexPrompt(): REGEX_PROMPT parameters should be given as REGEX_PROMPT<number> := \"value\".");
    errno = 0;
    size_t prompt_id = atoi(parameter_name + 12);
    if(errno) 
        error("addRegexPrompt(): error converting string \"%s\" in parameter name \"%s\" to number.", 
            parameter_name + 12, parameter_name);
    if(strlen(parameter_value) != 0)
    {
        log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
        prompt_list.set_prompt(prompt_id, parameter_value, TRUE);
    } 
    else
        error("addRegexPrompt(): Invalid parameter value: %s for parameter %s. "
                "REGEX_PROMPT parameter must contain at least one character!", 
                parameter_value, parameter_name);
    } 
    //if raw prompt
    else {
      if(strlen(parameter_name) < 17) 
        error("addRegexPrompt(): RAW_REGEX_PROMPT parameters should be given as RAW_REGEX_PROMPT<number> := \"value\".");
      errno = 0;
      size_t prompt_id = atoi(parameter_name + 16);
      if(errno) 
          error("addRegexPrompt(): error converting string \"%s\" in parameter name \"%s\" to number.", 
              parameter_name + 16, parameter_name);
      if(strlen(parameter_value) != 0)
      {
          log("Reading testport parameter: %s = %s", parameter_name, parameter_value );
          prompt_list.set_prompt(prompt_id, parameter_value, TRUE, TRUE);
      } 
      else
        error("addRegexPrompt(): Invalid parameter value: %s for parameter %s. "
                "REGEX_PROMPT parameter must contain at least one character!", 
                parameter_value, parameter_name);
    }// if raw prompt
}


void SSHCLIENTasp__PT::error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    TTCN_Logger::begin_event(TTCN_ERROR);
    TTCN_Logger::log_event("SSHCLIENTasp Test Port (%s): ", get_name());
    TTCN_Logger::log_event_va_list(fmt, ap);
    TTCN_Logger::end_event();
    va_end(ap);
    TTCN_error("Fatal error in SSHCLIENTasp Test Port %s (see above).", get_name());
}


void SSHCLIENTasp__PT::log_buffer(const char * logmsg, const unsigned char * buf, size_t buflen)
{
    if (debug)
    {

        TTCN_logger.log(TTCN_DEBUG, "%s: %s: ", port_name, logmsg);
        for(size_t j=0;j<buflen;)
        {
            TTCN_logger.begin_event(TTCN_DEBUG);
            for(size_t i=0;j<buflen && i<16;i++)
            {
                if(i == 8) TTCN_Logger::log_event("  ");
                TTCN_Logger::log_event("%02x ", buf[j++]);
            }
            TTCN_logger.end_event();
        }
    }
}


void SSHCLIENTasp__PT::log(const char *fmt, ...)
{
    if (debug)
    {
        va_list ap;
        va_start(ap, fmt);
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("SSHCLIENTasp Test Port (%s): ", get_name());
        TTCN_Logger::log_event_va_list(fmt, ap);
        TTCN_Logger::end_event();
        va_end(ap);
    }
}


char** SSHCLIENTasp__PT::add_params(int &num_of_par, char **params, const char *new_params){
  while(*new_params){
    while(*new_params<=' ' && *new_params) new_params++; // skip blanks
    if(*new_params=='\0') return params;
    while(*new_params>' '){
      params[num_of_par-1]=mputc(params[num_of_par-1],*new_params);
      new_params++;
    }
    num_of_par++;
    params=(char **)Realloc(params,num_of_par*sizeof(char*));
    params[num_of_par-1]=NULL;
  }
  
  return params;
}

Regex_Prompt_SSH_client::Regex_Prompt_SSH_client(const char *p_pattern, boolean raw_prompt)
{
    char *posix_str = NULL;

    if(raw_prompt){
      posix_str = mcopystr(p_pattern);
    } else {
      CHARSTRING cstr("(*)("); // string before prompt
      cstr = cstr + p_pattern; // prompt
      cstr = cstr + ")(*)";    // string after prompt
      posix_str = TTCN_pattern_to_regexp_sshclient(cstr);
    }

    if(posix_str == NULL) 
        TTCN_error("Cannot convert pattern \"%s\" to POSIX-equivalent.", p_pattern);
//    posix_str[strlen(posix_str)-1] = '\0'; // remove trailing "$"
    int ret_val=regcomp(&posix_regexp, posix_str, REG_EXTENDED); // +1 -> no ^
    TTCN_Logger::log(TTCN_DEBUG, "Translated pattern (%u subexpressions): %s", (unsigned int)posix_regexp.re_nsub, posix_str);
    Free(posix_str);
    if(ret_val!=0)
    {
        char err[512];
        regerror(ret_val, &posix_regexp, err, sizeof(err));
        regfree(&posix_regexp);
        TTCN_error("Function regcomp() failed while setting regexp pattern \"%s\" as prompt: %s", p_pattern, err);
    }
}


Regex_Prompt_SSH_client::~Regex_Prompt_SSH_client()
{
    regfree(&posix_regexp);
}


Regex_Prompt_MatchResult_SSH_client Regex_Prompt_SSH_client::match(const char *msg)
{
    Regex_Prompt_MatchResult_SSH_client ret_val;
    regmatch_t pmatch[4];
    int result = regexec(&posix_regexp, msg, 4, pmatch, 0);
//    for (int i=0;i<4;i++) TTCN_Logger::log(TTCN_DEBUG,
//    "result: %d, start: %u, end: %u", result, pmatch[i].rm_so,
//    pmatch[i].rm_eo);
    if(result == 0)
    {
        ret_val.match = TRUE;
        ret_val.start = pmatch[2].rm_so;
        ret_val.end = pmatch[2].rm_eo;
    }
    else if(result == REG_NOMATCH)
    {
        ret_val.match = FALSE;
        ret_val.start = 0;
        ret_val.end = 0;
    }
    else
    {
        char err[512];
        regerror(result, &posix_regexp, err, sizeof(err));
        TTCN_error("Error matching regexp prompt: %s", err);
    }
    return ret_val;
}


Prompt_List_SSH_client::~Prompt_List_SSH_client()
{
    clear();
}


void Prompt_List_SSH_client::set_prompt(unsigned int p_id, const char *p_prompt,
    boolean p_is_regex, boolean p_is_raw)
{
    size_t index;
    if( !id_to_index(p_id, index) )
    {
        index = n_elems++;
        if(n_elems==1) elems = (prompt_elem**)Malloc(sizeof(prompt_elem*));
        else elems = (prompt_elem**)Realloc(elems, n_elems*sizeof(prompt_elem*));
        if(!elems) TTCN_error("Not enough memory.");
    }
    else
    {
        if(elems[index]->is_regex) delete elems[index]->regex_prompt;
        else delete [](elems[index]->prompt);
        delete elems[index];
    }
    elems[index] = new prompt_elem;
    elems[index]->id = p_id;
    elems[index]->is_regex = p_is_regex;
    if(p_is_regex)
    {
        elems[index]->regex_prompt = new Regex_Prompt_SSH_client(p_prompt, p_is_raw);
    }
    else
    {
        elems[index]->prompt = new char[strlen(p_prompt)+1];
        strcpy(elems[index]->prompt, p_prompt);
    }
}


void Prompt_List_SSH_client::check(const char *warning_prefix)
{
    if(n_elems)
    {
        for(unsigned int i=0;i<n_elems-1;i++)
        {
            if(elems[i]->is_regex) continue;
            const char *pi = elems[i]->prompt;
            for(unsigned int j=i+1;j<n_elems;j++)
            {
                if(elems[j]->is_regex) continue;
                const char *pj = elems[j]->prompt;
                if(!strcmp(pi, pj))
                {
                    TTCN_warning("(%s): Prompt_List_SSH_client::check(): Duplicated prompt string '%s'.", warning_prefix, pi);
                    break;
                }
                else if(strstr(pi, pj))
                {
                    TTCN_warning("(%s): Prompt_List_SSH_client::check(): Using prompt '%s' that is a substring of prompt '%s' might cause problems.", warning_prefix, pj, pi);
                    break;
                }
                else if(strstr(pj, pi))
                {
                    TTCN_warning("(%s): Prompt_List_SSH_client::check(): Using prompt '%s' that is a substring of prompt '%s' might cause problems.", warning_prefix, pi, pj);
                    break;
                }
            }
        }
    }
}


void Prompt_List_SSH_client::clear()
{
    if(elems)
    {
        for(size_t i=0;i<n_elems;i++)
        {
            if(elems[i]->is_regex) delete elems[i]->regex_prompt;
            else delete [](elems[i]->prompt);
            delete elems[i];
        }
        Free(elems);
        elems = NULL;
    }
    n_elems = 0;
}


int Prompt_List_SSH_client::findPrompt(size_t &pos, const unsigned char *bufptr,
    size_t buflen) const
{
    char *buf_asciiz = NULL;
    for(size_t i=0;i<n_elems;i++)
    {
        if(elems[i]->is_regex == FALSE)
        {
            size_t prompt_len = strlen(elems[i]->prompt);
            if(prompt_len<=buflen)
            {
                if(strncmp(elems[i]->prompt, (const char *) (bufptr+buflen-prompt_len), prompt_len)==0)
                {
                    pos = buflen-prompt_len;
                    if(buf_asciiz) delete []buf_asciiz;
                    return prompt_len;
                }
            }
        }
        else
        {
            if(!buf_asciiz)
            {
                buf_asciiz = new char[buflen+1];
                memcpy(buf_asciiz, bufptr, buflen);
                buf_asciiz[buflen] = '\0';
            }
            Regex_Prompt_MatchResult_SSH_client result = elems[i]->regex_prompt->match(buf_asciiz);
            if(result.match)
            {
                pos = result.start;
                delete []buf_asciiz;
                return result.end - result.start;
            }
        }
    }
    if(buf_asciiz) delete []buf_asciiz;
    return -1;
}


boolean Prompt_List_SSH_client::id_to_index(unsigned int p_id, size_t &index) const
{
    for(index=0; index<n_elems; index++)
        if(elems[index]->id == p_id) return TRUE;
    return FALSE;
}
}

