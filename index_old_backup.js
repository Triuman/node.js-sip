//Nik Hendricks 10/13/23
const SIP = require('./SIP')
const { Streamer, Listener } = require('./RTP');
const utils = require('./utils')
a
class VOIP{
    constructor(props, callback){
        props = props || {};
        this.message_stack = []
        this.transport = this.create_transport(props);
        if(props.type == 'client'){
            this.UAC(props, callback);
        }else if(props.type == 'server'){
            this.UAS(props, callback);
        }
        this.rtpStreamer = null; // For sending RTP
        this.rtpListener = null; // For receiving RTP
        this.remoteMedia = {}; // Initialize remote media
        this.localMedia = { port: 5004 }; // Initialize local media
    }

// ---------------------------------------------------------
  // Start RTP streaming and listening
  // ---------------------------------------------------------
  startRTP(audioFilePath, codec = 'g711a') {
    if (!this.remoteMedia.ip || !this.remoteMedia.port) {
      console.error("Remote media information (IP/port) is missing.", this.remoteMedia);
      return;
    }

    console.log(`Starting RTP Stream to ${this.remoteMedia.ip}:${this.remoteMedia.port} using codec ${codec}`);

    // Start the RTP streamer to send audio
    this.rtpStreamer = new Streamer(audioFilePath, this.remoteMedia.ip, this.remoteMedia.port, codec, () => {
      console.log("RTP streaming completed.");
    });

    // Start the RTP listener to receive audio
    this.rtpListener = new Listener(this.localMedia.port, codec, (stream) => {
      console.log("Received audio stream:", stream);
      // You can process the audio stream further if needed
    });
  }

  // ---------------------------------------------------------
  // Stop RTP streaming and listening
  // ---------------------------------------------------------
  stopRTP() {
    if (this.rtpStreamer) {
      this.rtpStreamer.pause();
      console.log("RTP streaming paused.");
    }

    if (this.rtpListener) {
      this.rtpListener.stop();
      console.log("RTP listening stopped.");
    }
  }

    create_transport(props, callback){
        return SIP.Transport.new(props, callback);
    }

    UAS(props, callback){
    }

    UAC(props, callback){
        this.username = props.username;
        this.register_ip = props.register_ip;
        this.register_port = props.register_port;
        this.register_password = props.register_password;
        this.ip = props.transport.ip;
        this.port = props.transport.port;
        this.max_retries = 10;
        this.registration_interval = 10;
        this.registration_cseq = 1;
        console.log(props)

        this.register(props, (d) => {
            callback(d);
        })

        this.transport.on((msg) => {
            const res = SIP.Parser.parse(msg.toString());
            const headers = SIP.Parser.ParseHeaders(res.headers);
            const tag = headers.From.tag;
        
            // Extract the first branch if multiple branches are present
            let branch = headers.Via.branch;
            if (branch.includes(',')) {
                branch = branch.split(',')[0]; // Take the first branch as key
            }
        
            console.log('tag > ', tag);
            console.log('branch > ', branch);
            console.log('method > ', res.method || res.statusCode);
        
            console.log(this.message_stack);
            let cb = null;
        
            // Initialize message stack for missing tags and branches
            if (!this.message_stack[tag]) {
                this.message_stack[tag] = {};
            }
            if (!this.message_stack[tag][branch]) {
                this.message_stack[tag][branch] = [];
            }
        
            if (this.message_stack[tag][branch].length > 0) {
                const lastMessage = this.message_stack[tag][branch][this.message_stack[tag][branch].length - 1];
                if (lastMessage.callback) {
                    console.log('Running message_stack callback');
                    cb = lastMessage.callback;
                } else {
                    console.log('No callback found for message');
                }
                this.message_stack[tag][branch].push({ message: res });
                if (cb) {
                    cb(res);
                }
            } else {
                // Fallback if no messages exist in stack
                callback({
                    type: res.method || res.statusCode,
                    message: [res, this.message_stack[tag]],
                });
            }
        });
        
    }

    send(message, msg_callback) {
        const headers = SIP.Parser.ParseHeaders(message.headers);
        const tag = headers.From.tag;
        const branch = headers.Via.branch;
    
        // Ensure `this.message_stack` structure is initialized
        if (!this.message_stack[tag]) {
            this.message_stack[tag] = {};
        }
        if (!this.message_stack[tag][branch]) {
            this.message_stack[tag][branch] = [];
        }
    
        // Push the message into the stack
        this.message_stack[tag][branch].push({ message, callback: msg_callback });
    
        // Build and send the message
        const built = SIP.Builder.Build(message);
        this.transport.send(built, this.register_ip, 5060);
    }
    
    register(props, callback){
        var try_count = 0;
        var headers = {
            extension: this.username,
            ip: this.ip,
            port: this.port,
            requestUri: `sip:${this.register_ip}`,
            register_ip: this.register_ip,
            register_port: this.register_port,
            username: this.username,
            callId: props.callId || '123',
            cseq: this.registration_cseq,
            branchId: SIP.Builder.generateBranch(),
            from_tag: SIP.Builder.generateTag(),
        }

        const parseRemoteMedia = (finalResponse) => {
            if (!finalResponse || !finalResponse.headers || !finalResponse.headers.Contact) {
                console.error("Invalid response or missing Contact header.");
                return null;
            }
        
            const contactHeader = finalResponse.headers.Contact;
            console.log("Contact header:", contactHeader);
        
            // Split Contact header into individual entries
            const contacts = contactHeader.split(',');
        
            // Parse each Contact entry to find the most relevant one
            let remoteMedia = null;
            let longestExpiry = 0;
        
            for (const contact of contacts) {
                const match = contact.match(/<sip:([^@]+)@([^:]+):(\d+)>;expires=(\d+)/);
                const receivedMatch = contact.match(/received="sip:([^:]+):(\d+)"/);
        
                if (match) {
                    const username = match[1];
                    const ip = receivedMatch ? receivedMatch[1] : match[2];
                    const port = receivedMatch ? receivedMatch[2] : match[3];
                    const expires = parseInt(match[4], 10);
        
                    console.log(`Parsed contact: username=${username}, ip=${ip}, port=${port}, expires=${expires}`);
        
                    // Choose the contact with the longest expiration time
                    if (expires > longestExpiry) {
                        longestExpiry = expires;
                        remoteMedia = { ip, port: parseInt(port, 10), expires };
                    }
                }
            }
        
            if (!remoteMedia) {
                console.error("No valid Contact entry found.");
                return null;
            }
        
            console.log("Selected remoteMedia:", remoteMedia);
            return remoteMedia;
        };

        const sendRegister = (challenge_headers, proxy_auth = false) => {
            try_count++;
            this.registration_cseq++;
            if(try_count > this.max_retries){
                console.log('Max retries reached');
                callback({type:'REGISTER_FAILED', message:{statusCode:408, statusText:'Request Timeout'}});
                return;
            }

            this.send(SIP.Builder.SIPMessageObject('REGISTER', headers), (response) => {
                console.log("Register response", response);
                
                const parsedHeaders = SIP.Parser.ParseHeaders(response.headers);
                const challengeData = parsedHeaders['WWW-Authenticate'] || parsedHeaders['Proxy-Authenticate'];
            
                // Increment CSeq and set credentials
                headers.cseq += 1;
                headers.username = this.username;
                headers.password = this.register_password;
            
                // Handle the challenge if provided
                this.send(
                    SIP.Builder.SIPMessageObject(
                        'REGISTER',
                        headers,
                        challengeData,
                        parsedHeaders['Proxy-Authenticate'] !== undefined
                    ),
                    (finalResponse) => {
                        console.log("finalResponse", finalResponse);
                        
                        if (finalResponse.statusCode === 200) {
                             // Parse remoteMedia from the Contact header
        this.remoteMedia = parseRemoteMedia(finalResponse);

        if (this.remoteMedia) {
            console.log(`Remote media set: IP=${this.remoteMedia.ip}, Port=${this.remoteMedia.port}`);
        } else {
            console.error("Failed to set remote media.");
        }

        const expires = this.remoteMedia ? this.remoteMedia.expires : 3600; // Default to 3600 if not available
        console.log(`REGISTERED for ${expires} seconds`);

        setTimeout(() => {
            console.log("Re-registering before expiration...");
            props.callId = SIP.Builder.generateBranch();
            this.register(props, callback);
        }, expires * 1000);

        callback({ type: 'REGISTERED', message: finalResponse });
                        } else if (finalResponse.statusCode === 401) {
                            // Unauthorized - Retry with the new challenge
                            const newChallengeData = SIP.Parser.ParseHeaders(finalResponse.headers)['WWW-Authenticate'];
                            sendRegister(newChallengeData, false);
                        } else if (finalResponse.statusCode === 403) {
                            // Forbidden - Registration failed
                            console.error(`Registration failed: ${finalResponse.statusCode} ${finalResponse.statusText}`);
                            callback({ type: 'REGISTER_FAILED', message: finalResponse });
                        } else if (finalResponse.statusCode === 407) {
                            // Proxy authentication required - Retry with the new challenge
                            const newChallengeData = SIP.Parser.ParseHeaders(finalResponse.headers)['Proxy-Authenticate'];
                            sendRegister(newChallengeData, true);
                        } else {
                            // Unexpected status code
                            console.error('Unexpected status code:', finalResponse.statusCode, finalResponse.statusText);
                            callback({ type: 'REGISTER_FAILED', message: finalResponse });
                        }
                    }
                );
            });
            
        }

        sendRegister();
    }

    unregister(callback) {
        // We'll do a similar approach to the register method
        let try_count = 0;
        let max_retries = 5; // You can set your own max
        let headers = {
          extension: this.username,
          ip: this.ip,
          port: this.port,
          requestUri: `sip:${this.register_ip}`,
          register_ip: this.register_ip,
          register_port: this.register_port,
          username: this.username,
          callId: SIP.Builder.generateBranch(),
          cseq: ++this.registration_cseq,     // increment the registration CSeq
          branchId: SIP.Builder.generateBranch(),
          from_tag: SIP.Builder.generateTag(),
          expires: 0, // This is the key for unregistering
        };
      
        const sendUnregister = (challengeData, proxyAuth = false) => {
          try_count++;
          if (try_count > max_retries) {
            console.log("Unregister: Max retries reached");
            if (callback) callback({ type: "UNREGISTER_FAILED", message: { statusCode: 408, statusText: "Request Timeout" } });
            return;
          }
      
          // Build and send the REGISTER with expires=0 and (optional) authorization
          this.send(SIP.Builder.SIPMessageObject("REGISTER", headers, challengeData, proxyAuth), (response) => {
            if (response.statusCode === 200) {
              console.log("Successfully unregistered from the SIP server.");
              if (callback) callback({ type: "UNREGISTERED", message: response });
            } else if (response.statusCode === 401) {
              // Handle WWW-Authenticate challenge
              const newChallenge = SIP.Parser.ParseHeaders(response.headers)["WWW-Authenticate"];
              // Increment the CSeq to respond properly to the challenge
              headers.cseq = ++this.registration_cseq;
              headers.password = this.register_password;
              sendUnregister(newChallenge, false);
            } else if (response.statusCode === 407) {
              // Handle Proxy-Authenticate challenge
              const newChallenge = SIP.Parser.ParseHeaders(response.headers)["Proxy-Authenticate"];
              headers.cseq = ++this.registration_cseq;
              headers.password = this.register_password;
              sendUnregister(newChallenge, true);
            } else {
              console.log("Unregister: Unexpected status code:", response.statusCode, response.statusText);
              if (callback) callback({ type: "UNREGISTER_FAILED", message: response });
            }
          });
        };
      
        // Start the unregister logic
        sendUnregister();
      }
      

    call(extension, ip, port, msg_callback){
        var cseq = 1;
        var try_count = 0;
        let b = SIP.Builder.generateBranch();
        var sdp = ` v=0
                    o=- 0 0 IN IP4 ${utils.getLocalIpAddress()}
                    s=Easy Muffin
                    c=IN IP4 ${utils.getLocalIpAddress()}
                    t=0 0
                    a=tool:libavformat 60.16.100
                    m=audio 10326 RTP/AVP 0
                    b=AS:64`.replace(/^[ \t]+/gm, '');
        
        let h = {
            extension: extension,
            ip: ip,
            port: port,
            register_ip: this.register_ip,
            register_port: this.register_port,
            username: this.username,
            callId: SIP.Builder.generateBranch(),
            cseq: cseq,
            branchId: SIP.Builder.generateBranch(),
            from_tag: SIP.Builder.generateTag(),
            body: sdp,
            password: this.register_password,
            requestUri: `sip:${extension}@${ip}:${port}`,
        };
        
        const sendInvite = (challenge_headers, proxy_auth = false) => {
            try_count++;
            if(try_count > this.max_retries){
                console.log('Max retries reached');
                //this.message_stack[h.from_tag].pop();
                msg_callback({type:'CALL_FAILED', message:{statusCode:408, statusText:'Request Timeout'}});
                return;
            }
            this.send(SIP.Builder.SIPMessageObject('INVITE', h, challenge_headers, proxy_auth), (response) => {
                if(response.statusCode == 400){
                    console.log('400 Bad Request');
                    //delete this.message_stack[tag]
                    //this.call(extension, ip, port, msg_callback); //retry
                    return;
                }else if (response.statusCode == 401) {
                    let challenge_data = SIP.Parser.ParseHeaders(response.headers)['WWW-Authenticate'];
                    sendInvite(challenge_data, false);
                }else if(response.statusCode == 407){
                    let challenge_data = SIP.Parser.ParseHeaders(response.headers)['Proxy-Authenticate'];
                    sendInvite(challenge_data, true);
                }else if (response.statusCode == 100) {
                    console.log('100 Trying');
                    return;
                }else if (response.statusCode == 403) {
                    console.log('403 Forbidden');
                    //delete this.message_stack[tag];
                    msg_callback({type:'CALL_REJECTED', message:response});
                    return;
                }else if (response.statusCode == 183) {
                    console.log('183 Session Progress');
                }else if (response.statusCode == 200) {
                    let headers = SIP.Parser.ParseHeaders(response.headers);
                    this.send({
                        isResponse: false,
                        protocol: 'SIP/2.0',
                        method: 'ACK',
                        requestUri: `sip:${extension}@${ip}:${port}`,
                        headers: {
                            'Via': `SIP/2.0/UDP ${headers.Via.uri.ip}:${headers.Via.uri.port || 5060};branch=${headers.Via.branch}`,
                            'To': `<sip:${headers.To.contact.username}>`,
                            'From': `<sip:${headers.From.contact.username}@${headers.Via.uri.ip}:${headers.Via.uri.port || 5060}>;tag=${headers.From.tag}`,
                            'Call-ID': headers['Call-ID'],
                            'CSeq': `${headers.CSeq.count} ${headers.CSeq.method}`,
                            'Contact': `<sip:${headers.From.contact.username}@${headers.Via.uri.ip}:${headers.Via.uri.port || 5060}>`,
                            'Max-Forwards': SIP.Builder.max_forwards,
                            'User-Agent': SIP.Builder.user_agent,
                        },
                        body: ''
                    })

                    msg_callback({type:'CALL_CONNECTED', message:response});
                    return;
                }else if (response.method != undefined && response.method == 'BYE') {
                    console.log('BYE Received');
                    //this.bye(response);
                    return;
                }else {
                    console.error('Unexpected status code:', response.statusCode);
                }
            });
        };
        
        sendInvite();
    }

    accept(message){
        var cseq = 1;
        var headers = SIP.Parser.ParseHeaders(message.headers);
        message.isResponse = true;
        message.statusCode = '100 Trying';
        var old_body = message.body;
        message.body = '';
        message.headers['Contact'] = `<sip:${headers.To.contact.username}@${headers.Via.uri.ip}:${headers.Via.uri.port || 5060}>`
        this.send(message)
        message.statusCode = '180 Ringing';
        this.send(message)
        message.body = `v=0
                        o=- 123456789 123456789 IN IP4 192.168.1.110
                        s=Asterisk Call
                        c=IN IP4 192.168.1.110
                        t=0 0
                        m=audio 5005 RTP/AVP 8
                        a=rtpmap:8 PCMA/8000
                        a=fmtp:8 0-15`.replace(/^[ \t]+/gm, '');
        message.statusCode = '200 OK';
        this.send(message)
    }

    reject(message){
        var headers = SIP.Parser.ParseHeaders(message.headers);
        console.log(headers)
        headers.CSeq.count = headers.CSeq.count + 1;
        var new_message = {
            statusCode: '486 Busy Here',
            isResponse: true,
            protocol: 'SIP/2.0',
            headers: {
                'Via': `SIP/2.0/UDP ${headers.Via.uri.ip}:${headers.Via.uri.port || 5060};branch=${headers.Via.branch}`,
                'To': `<sip:${headers.To.contact.username}>`,
                'From': `<sip:${headers.From.contact.username}@${headers.Via.uri.ip}:${headers.Via.uri.port || 5060}>;tag=${headers.From.tag}`,
                'Call-ID': headers['Call-ID'],
                'CSeq': `${headers.CSeq.count} ${headers.CSeq.method}`,
                'Contact': `<sip:${headers.From.contact.username}@${headers.Via.uri.ip}:${headers.Via.uri.port || 5060}>`,
                'Max-Forwards': SIP.Builder.max_forwards,
                'User-Agent': SIP.Builder.user_agent,
                'Content-Length': '0',
            },
            body: ''
        }
        this.send(new_message)
    }

    bye(message){
        var headers = SIP.Parser.ParseHeaders(message.headers);
        message.isResponse = false;
        message.method = 'BYE';
        message.headers['Contact'] = `<sip:${headers.From.contact.username}@${headers.Via.uri.ip}:${headers.Via.uri.port || 5060}>`
        message.headers['To'] = `<sip:${headers.To.contact.username}@${headers.Via.uri.ip}:${headers.Via.uri.port || 5060}>`
        message.headers['From'] = `<sip:${headers.From.contact.username}@${headers.Via.uri.ip}:${headers.Via.uri.port || 5060}>tag=${headers.From.tag}`
        this.send(message)

    }

    ok(message){
        var headers = SIP.Parser.ParseHeaders(message.headers);
        console.log(headers)
        var new_message = {
            statusCode: '200 OK',
            isResponse: true,
            protocol: 'SIP/2.0',
            headers: {
                'Via': `SIP/2.0/UDP ${headers.Via.uri.ip}:${headers.Via.uri.port || 5060};branch=${headers.Via.branch}`,
                'To': `<tel:${headers.To.contact.username}>`,
                'From': `<sip:${headers.From.contact.username}@${headers.Via.uri.ip}:${headers.Via.uri.port || 5060}>;tag=${headers.From.tag}`,
                'Call-ID': headers['Call-ID'],
                'CSeq': `${headers.CSeq.count} ${headers.CSeq.method}`,
                'Contact': `<sip:${headers.From.contact.username}@${headers.Via.uri.ip}:${headers.Via.uri.port || 5060}>`,
                'Max-Forwards': SIP.Builder.max_forwards,
                'User-Agent': SIP.Builder.user_agent,
            },
            body: ''
        }
        this.transport.send(SIP.Builder.Build(new_message), headers.Via.uri.ip, headers.Via.uri.port)
    }

    message(extension, body){
        var headers = {
            extension: extension,
            ip: this.register_ip,
            listen_ip: utils.getLocalIpAddress(),
            listen_port: 5060,
            username: this.username,
            callId: SIP.Builder.generateBranch(),
            cseq: 1,
            branchId: SIP.Builder.generateBranch(),
            body: body,
        }

       
        this.send(SIP.Builder.SIPMessageObject('MESSAGE', headers))

    }
}

module.exports = VOIP;