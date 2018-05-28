## Compilation and execution of TTCN-3 code
1. Compilation of TTCN-3 to C++ code: `ttcn3_compiler -t *.ttcn`
2. Makefile generation: `ttcn3_makefilegen -f -t rest.tpd` 
3. Compilation in `./build` repository: `make` 
4. Execution in `./build` : `ttcn3_start ./HTTPmsgTest ../config.cfg` 

## Configuration file  

[LOGGING]
LogFile := "log/MoonGen-%n.log"  #the log file path, %n = client in the current case 
FileMask := LOG_ALL |TTCN_PORTEVENT | TTCN_DEBUG | ERROR | TESTCASE | STATISTICS | MATCHING
ConsoleMask := LOG_ALL |TTCN_PORTEVENT | TTCN_DEBUG | ERROR | TESTCASE | STATISTICS  | MATCHING
SourceInfoFormat := Single
LogSourceInfo := Stack

[MODULE_PARAMETERS]
HttpServerHostName := "10.30.0.253" #the destination ip 
HttpServerPort := 80 #the destination port
HTTPClientUseSSL := false #no ssl is used

//the values in the POST message
PX_INPUT_EP := "10.0.0.10"; #NS input endpoint IP
PX_OUTPUT_EP := "10.0.0.10"; #NS output endpoint IP
PX_BANDWIDTH := "20";  #Test bandwidth
PX_EX_TIME := "10";  #Test execution time
PX_TEST_ID := "2EufePrpPtbyvyrF7";  #Test ID
PX_MOONGEN_OUT_PORT := "2";  #MoonGen outbound traffic port
PX_MOONGEN_IN_PORT := "3";  #Moongen inbound traffic port


PX_EXPECTED_RESULT := "done"; #the message to determine that the test has finished. in the example, it's "done"
PX_EXPECTED_LANTENCY := "10"; # the max latency allowed
PX_EXPECTED_PACKET_LOSS := ""; #the percentage of packet loss accepted


[TESTPORT_PARAMETERS]
\#system.HTTP_client_port.VERIFYCERTIFICATE := "no"
*.HTTP_client_port.http_debugging := "yes" # "no" to turn of the debugging logs
*.HTTP_client_port.use_notification_ASPs := "no"


[MAIN_CONTROLLER]
KillTimer := 1
TCPPort := 9036

[EXECUTE]
\# comment or de-comment the test to be executer
\#HTTP_Test.tc_http_sendTest  #POST a message to trigger the moogen test
HTTP_Test.tc_http_getResult #GET the test result. A polling is scheduled every PX_EX_TIME second. 