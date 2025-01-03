//Nik Hendricks 10/13/23
const dgram = require('dgram')

const Transports = {
    socket: null,
    type: null,
    new: (props) => {
        Transports[props.transport.type](props)
        return Transports;
    },

    UDP: (props) => {
        Transports.type = 'UDP';
        Transports.socket = dgram.createSocket('udp4')
        Transports.socket.bind(props.port, props.ip)
    },

    TCP:(props) => {
        Transports.type = 'TCP';
        Transports.socket = dgram.createSocket('tcp4')
        Transports.socket.bind(props.port, props.ip)
    },

    send: (message, ip, port) => {
        console.log('Sending Message')
        console.log(message.toString())
        Transports.socket.send(message, port, ip)
    },

    on: (callback) => {
        Transports.socket.on('message', (msg, rinfo) => {
            console.log('Received Message')
            console.log(msg.toString())
            callback(msg);
        })
    }
}

module.exports = Transports;