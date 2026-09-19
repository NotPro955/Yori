// WebSocket Connection Manager with exponential backoff reconnect

export class WebSocketManager {
  constructor(wsUrl, onMessage, onStatusChange, logger = console.log) {
    this.wsUrl = wsUrl;
    this.onMessage = onMessage;
    this.onStatusChange = onStatusChange; // 'connected', 'reconnecting', 'disconnected'
    this.logger = logger;

    this.ws = null;
    this.reconnectAttempts = 0;
    this.reconnectTimer = null;
    this.isExplicitClose = false;
  }

  connect() {
    this.isExplicitClose = false;
    if (this.ws) {
      try { this.ws.close(); } catch (e) {}
    }

    this.onStatusChange('reconnecting', 'Connecting...');

    try {
      this.ws = new WebSocket(this.wsUrl);
    } catch (err) {
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.reconnectAttempts = 0;
      this.onStatusChange('connected', 'Connected');
    };

    this.ws.onmessage = (event) => {
      try {
        const packet = JSON.parse(event.data);
        this.onMessage(packet);
      } catch (err) {
        this.logger(`[error] failed to parse incoming packet: ${err.message}`);
      }
    };

    this.ws.onclose = () => {
      if (!this.isExplicitClose) {
        this.onStatusChange('disconnected', 'Disconnected');
        this.scheduleReconnect();
      }
    };

    this.ws.onerror = () => {
      // triggers onclose
    };
  }

  send(packet) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return false;
    }
    this.ws.send(JSON.stringify(packet));
    return true;
  }

  scheduleReconnect() {
    if (this.reconnectTimer || this.isExplicitClose) return;

    // Exponential backoff: 1s, 2s, 4s, 8s, 10s max
    const delay = Math.min(10000, 1000 * Math.pow(2, this.reconnectAttempts));
    this.reconnectAttempts += 1;

    this.onStatusChange('reconnecting', `Reconnecting in ${Math.round(delay / 1000)}s...`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  disconnect() {
    this.isExplicitClose = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.onStatusChange('disconnected', 'Disconnected');
  }
}
