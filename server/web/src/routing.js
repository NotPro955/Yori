// Relay route selection and circuit management

export function selectRoute(peers, selfUsername, recipientUsername) {
  // Candidate relays must not be sender or recipient and must have presession_pub
  const candidates = peers.filter(p => 
    p.username !== selfUsername && 
    p.username !== recipientUsername && 
    (p.presession_pub || p.pre_session_key)
  );

  if (candidates.length < 2) {
    return null; // Not enough peers for 2-hop onion route
  }

  // Cryptographically random shuffle using crypto.getRandomValues
  const shuffled = [...candidates];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const randBuf = new Uint32Array(1);
    crypto.getRandomValues(randBuf);
    const j = randBuf[0] % (i + 1);
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }

  return [
    {
      username: shuffled[0].username,
      presession_pub: shuffled[0].presession_pub || shuffled[0].pre_session_key
    },
    {
      username: shuffled[1].username,
      presession_pub: shuffled[1].presession_pub || shuffled[1].pre_session_key
    }
  ];
}

export class CircuitManager {
  constructor(getPeers, selfUsername, onRotate) {
    this.getPeers = getPeers;
    this.selfUsername = selfUsername;
    this.onRotate = onRotate;
    this.circuits = new Map(); // recipient -> { circuitID, route, timer }
  }

  getCircuit(recipient) {
    let circuit = this.circuits.get(recipient);
    if (!circuit) {
      circuit = this.createCircuit(recipient);
    }
    return circuit;
  }

  createCircuit(recipient) {
    const peers = this.getPeers();
    const route = selectRoute(peers, this.selfUsername, recipient);
    if (!route) {
      return null;
    }

    const randBytes = crypto.getRandomValues(new Uint8Array(8));
    const circuitID = Array.from(randBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    const existing = this.circuits.get(recipient);
    if (existing && existing.timer) {
      clearInterval(existing.timer);
    }

    const timer = setInterval(() => {
      this.rotateCircuit(recipient);
    }, 60000); // 60 seconds rotation

    const circuit = {
      circuitID,
      route, // [relay1, relay2]
      timer
    };

    this.circuits.set(recipient, circuit);
    return circuit;
  }

  rotateCircuit(recipient) {
    const peers = this.getPeers();
    const newRoute = selectRoute(peers, this.selfUsername, recipient);
    if (newRoute) {
      const randBytes = crypto.getRandomValues(new Uint8Array(8));
      const circuitID = Array.from(randBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      const current = this.circuits.get(recipient);
      if (current) {
        current.circuitID = circuitID;
        current.route = newRoute;
      }
      if (this.onRotate) {
        this.onRotate(recipient, circuitID, newRoute);
      }
    }
  }

  stopAll() {
    for (const c of this.circuits.values()) {
      if (c.timer) clearInterval(c.timer);
    }
    this.circuits.clear();
  }
}
