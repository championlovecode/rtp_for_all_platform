
#include "test.h"
#include <pjlib.h>
#include <pjmedia.h>
#include "stream_rtp_send_rece.h"

void how_to_call()
{
    struct info_rtp info_rtp_temp;
    memset(&info_rtp_temp,0,sizeof(info_rtp_temp));
    
    info_rtp_temp.codec_id="pcma";  	//使用的编解码库   
    info_rtp_temp.local_port = 4001;	//local port
    info_rtp_temp.remote_addr = "172.26.49.2";  //server ip
    info_rtp_temp.remote_port = 4003;    //remote port  
    
    /*Use the function to Send and receive the RTPS*/
    main_rtp_send_rece(&info_rtp_temp);
    return;
}