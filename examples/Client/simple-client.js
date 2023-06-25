const SIP = require("../../SIP.js");
const SIPMessage = require("../../SIPMessage.js");
const SDPParser = require("../../SDPParser.js");
const Parser = require("../../Parser.js");
const RTP = require("../../RTP.js");
const MediaStream = require("../../Media.js");
const Builder = require("../../Builder.js");
require('dotenv').config({ path: 'CONFIG.env' });

const asteriskDOMAIN = process.env.ASTERISK_DOMAIN;
const asteriskIP = process.env.ASTERISK_IP;
const asteriskPort = process.env.ASTERISK_PORT;
const clientIP = process.env.CLIENT_IP;
const clientPort = process.env.CLIENT_PORT;
const username = process.env.USERNAME;
const password = process.env.PASSWORD;
let callId;
var Client = new SIP({ip: asteriskIP, port: asteriskPort, username: username, password: password, client_ip: clientIP, client_port: clientPort})

Client.Socket.bind(clientPort, "192.168.1.2")


//should make transaction and dialog objects just behaviors of the SIP class.
//you can use either one to send SIP messages.





Client.Listen();

Client.Register().then(dialog => {
    console.log("REGISTERED")
    call("201");
})

//receive a call
//Client.on('INVITE', (res) => {
//    console.log("Received INVITE")
//    var d = Client.Dialog(res).then(dialog => {
//        console.log("RESPONSE")
//        dialog.send(res.CreateResponse(100))
//        dialog.send(res.CreateResponse(180))
//        dialog.send(res.CreateResponse(200))
//
//        console.log(res.ParseSDP())
//        
//        dialog.on('BYE', (res) => {
//            console.log("BYE")
//            dialog.send(res.CreateResponse(200))
//            dialog.kill()
//        })
//
//        
//
//    })
//})

Client.on('INVITE', (res) => {
    console.log("Received INVITE");

    // Determine the new target location (extension) for redirection
    var newExtension = `73@${asteriskIP}`;
    
    // Create a SIP 302 Moved Temporarily response
    var redirectResponse = res.CreateResponse(302);
    redirectResponse.headers.Contact = `<sip:${newExtension}>`;

    // Send the redirect response
    var d = Client.Dialog(res).then(dialog => {
        dialog.send(redirectResponse);
        // Optionally, you can send additional provisional responses (e.g., 180 Ringing) if desired
        dialog.send(res.CreateResponse(180));
   
        dialog.on('BYE', (res) => {
            console.log("BYE");
            dialog.send(res.CreateResponse(200));
            dialog.kill();
        });
    });
});


//function to make a call
var call = (extension) => {
    var media;
    var message = Client.Message({
        isResponse: false,
        protocol: "SIP/2.0",
        method: "INVITE",
        requestUri: `sip:${extension}@${asteriskDOMAIN}`,
        headers: {
            'Via': `SIP/2.0/UDP ${clientIP}:${clientPort};branch=${Builder.generateBranch()}`,
            'From': `<sip:${username}@${asteriskDOMAIN}>;tag=${Builder.generateBranch()}`,
            'To': `<sip:${extension}@${asteriskDOMAIN}>`,
            'Call-ID': `${Builder.generateBranch()}@${clientIP}`,
            'CSeq': `1 INVITE`,
            'Contact': `<sip:${username}@${clientIP}:${clientPort}>`,
            'Max-Forwards': '70',
            'User-Agent': 'Node.js SIP Library',
            'Content-Type': 'application/sdp',
            'Content-Length': '0'
        },
        body: ''
    })

    Client.send(message)

    var d = Client.Dialog(message).then(dialog => {
        
        
        dialog.on('401', (res) => {
            var a = message.Authorize(res); //generate authorized message from the original invite request
            console.log(`authorize message for ${extension}`)
            dialog.send(a)
        })

        dialog.on('200', (res) => {
            console.log(`200 OK ext: ${extension}`)
            console.log(res.ParseSDP())
            //dialog.send(res.CreateResponse(''))
            console.trace()
            //media.start()
        })

        dialog.on('INVITE', (res) => {
            console.log(`INVITE from ${extension}`)
            console.log(res.ParseSDP())
            //media.start()
        })

        dialog.on('180', (res) => {
            console.log(`Ringing ${extension}`)
        })

        dialog.on('BYE', (res) => {
            console.log(`BYE from ${extension}`)
            var p = {
                extension: username,
                branchId: Parser.getBranch(res),
                callId: Parser.getCallId(res),
                cseq: Parser.getCseq(res),
            }
            var ok_response = Client.Message("200", p).create();
            dialog.send(ok_response.message);
        })
    })
}

//setInterval(() => {
//    console.log("____ CLIENT DIALOGS ____\n\n")
//    console.log(Client.dialogs)
//    console.log("\n\n")
//    console.log("____ CLIENT TRANSACTIONS ____\n\n")
//    console.log(Client.transactions)
//}, 5000);