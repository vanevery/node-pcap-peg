// VERY VERY imperfect example of using node pcap.
// Right now it only captures the first packet of image data rendering an incomplete image file
// Etherpeg http://www.etherpeg.org/ inspired
// Lots of code borrowed from Herbivore: https://github.com/samatt/Herbivore

var fs = require('fs');
var pcap = require('pcap'),
tcp_tracker = new pcap.TCPTracker(),
pcap_session = pcap.createSession('en0', "ip proto \\tcp");
 
// tcp_tracker.on('session', function (session) {
// //  console.log("Start of session between " + session.src_name + " and " + session.dst_name);
//   session.on('end', function (session) {
// //	  console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
//   });
// });

var count = 0;
 
pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
	var parsed = _parse(packet, raw_packet);
	if (parsed.payload && parsed.payload.http) {
		console.log(parsed.payload);
		
		// If it's an image, save it
		if (parsed.payload.contentType == 'image/gif') {
			if (parsed.payload.payload && parsed.payload.payload.length > 0) {
				var binaryImage = new Buffer(parsed.payload.payload, 'base64');
				fs.writeFileSync(__dirname + '/image' + count + '.gif', binaryImage);
				count++;
			}
		} else if (parsed.payload.contentType == 'image/jpeg') {
			if (parsed.payload.payload && parsed.payload.payload.length > 0) {
				var binaryImage = new Buffer(parsed.payload.payload, 'base64');
				fs.writeFileSync(__dirname + '/image' + count + '.jpg', binaryImage);
				count++;
			}
		}

	}
	//console.log(packet.payload.payload.payload.data);
    // tcp_tracker.track_packet(packet);
});


// The following functions are shamelessly stolen from the amazing Herbivore application:
// https://github.com/samatt/Herbivore
function _parse (packet, raw) {
    const ts = packet.pcap_header.tv_sec
    const eth = packet.payload
    const ip = eth.payload
    const tcp = ip.payload
    const src = ip.saddr.addr.join('.')
    const dst = ip.daddr.addr.join('.')

    if (tcp.sport === 8443 ||
        tcp.sport === 443 ||
        tcp.dport === 443 ||
        tcp.dport === 8443) {
      if (tcp.data) {
    //    if (tlsClientHello(tcp.data)) {
          return {ts: ts, eth: eth, ip: ip, tcp: tcp, payload: { type: 'https', host: tcp.data }}
    //    }
      }
      return false
    }

    if (!tcp.data) {
      return false
    }

    const rBuffer = tcp.data
    const r = tcp.data.toString('utf-8')

    if (r.indexOf('Content-Length') === -1 &&
        r.indexOf('Host') === -1 &&
        r.indexOf('Content-Type') === -1) {
      return false
    }

    const httpr = r.split('\r\n')
    try {
      return { ts: ts, eth: eth, ip: ip, tcp: tcp, payload: parseHTTP(httpr, rBuffer), raw: r }
    } catch (err) {
      console.log(err)
      return false
    }
}


function findFileSignature (arr, val, val2, val3) {
    let indexes = []
    for (let i = 0; i < arr.length; i++) {
      if (arr[i] === val) {
        indexes.push(i)
      }
    }
    // Look for the first three decimal values of the image file signature
    // If found, convert to base64
    for (let j = 0; j < indexes.length; j++) {
      if (arr[indexes[j] + 1] === val2) {
        if (arr[indexes[j] + 2] === val3) {
          const sliced = arr.slice(indexes[j]).toString('base64')
          return sliced
        }
      }
    }
}

function parseHTTP (headers, buffer) {
	const packet = {}
	packet.http = true
	packet.host = ''
	const firstline = headers.shift()
	if (firstline.indexOf('GET') > -1 ||
		firstline.indexOf('POST') > -1 ||
		firstline.indexOf('PUT') > -1) {
	  const [verb, url, version] = firstline.split(' ')
	  packet.type = 'request'
	  packet.method = verb
	  packet.url = url
	  packet.version = version
	} else {
	  const [version, code, status] = firstline.split(' ')
	  packet.type = 'response '
	  packet.code = code
	  packet.status = status
	  packet.version = version
	}

	packet.headers = []
	packet.contentType = 'none'
	for (var i = 0; i < headers.length; i++) {
	  if (headers[i] === '') {
		break
	  }
	  const header = headers[i].split(': ')
	  if (header.length < 2) {
		continue
	  } else {
		if (header[0].indexOf('Host') > -1) {
		  packet.host = header[1]
		}
		if (header[0].indexOf('Content-Type') > -1) {
		  packet.contentType = header[1]
		}
		packet.headers.push([header[0], header[1]])
	  }
	}
	// if (!hasContentHeader) {
	//   packet.contentType = ''
	// }
	// headers.pop()
	if (buffer.indexOf('Content-Type: image') !== -1) {
	  if (buffer.indexOf('png') !== -1) {
		const fileSignature = [137, 80, 78]
		packet.payload = findFileSignature(buffer, fileSignature[0], fileSignature[1], fileSignature[2])
	  }
	  if (buffer.indexOf('jpeg') !== -1) {
		const fileSignature = [255, 216, 255]
		packet.payload = findFileSignature(buffer, fileSignature[0], fileSignature[1], fileSignature[2])
	  }
	  if (buffer.indexOf('gif') !== -1) {
		const fileSignature = [71, 73, 70]
		packet.payload = findFileSignature(buffer, fileSignature[0], fileSignature[1], fileSignature[2])
	  }
	} else {
	  const lastline = headers.splice(headers.length - 1)
	  packet.payload = lastline
	}
	return packet
}

