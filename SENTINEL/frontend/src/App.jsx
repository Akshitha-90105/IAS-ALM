
import { useEffect, useState } from 'react'
import './App.css'

function App() {
  // Dashboard data
  const [alerts, setAlerts] = useState([])
  const [events, setEvents] = useState([])
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [backendOnline, setBackendOnline] = useState(false)

  // Firewall form state
  const [ruleName, setRuleName] = useState('')
  const [protocol, setProtocol] = useState('TCP')
  const [port, setPort] = useState('')
  const [action, setAction] = useState('BLOCK')
  const [ruleMessage, setRuleMessage] = useState('')

  // Packet evaluation state
  const [sourceIP, setSourceIP] = useState('192.168.1.100')
  const [destinationIP, setDestinationIP] = useState('192.168.1.1')
  const [packetProtocol, setPacketProtocol] = useState('TCP')
  const [packetPort, setPacketPort] = useState('4444')
  const [packetResult, setPacketResult] = useState(null)
  const [packetMessage, setPacketMessage] = useState('')
  const [checkingPacket, setCheckingPacket] = useState(false)

  // Anomaly detection state
  const [trafficData, setTrafficData] = useState(
    '98,100,102,103,101,99,100'
  )
  const [currentValue, setCurrentValue] = useState('115')
  const [threshold, setThreshold] = useState('3')
  const [anomalyResult, setAnomalyResult] = useState(null)
  const [anomalyMessage, setAnomalyMessage] = useState('')
  const [checkingAnomaly, setCheckingAnomaly] = useState(false)

  // Add a firewall rule
  const addFirewallRule = async (e) => {
    e.preventDefault()
    setRuleMessage('')

    try {
      const response = await fetch(
        'http://127.0.0.1:8000/firewall/rules',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name: ruleName,
            protocol,
            port: port ? Number(port) : null,
            action,
            enabled: true,
          }),
        }
      )

      if (!response.ok) {
        throw new Error('Could not create firewall rule')
      }

      const newRule = await response.json()

      setRules((previousRules) => [...previousRules, newRule])
      setRuleName('')
      setProtocol('TCP')
      setPort('')
      setAction('BLOCK')
      setRuleMessage('Firewall rule added successfully!')
    } catch (error) {
      setRuleMessage(error.message)
    }
  }

  // Evaluate a network packet
  const evaluatePacket = async (e) => {
    e.preventDefault()
    setPacketMessage('')
    setPacketResult(null)
    setCheckingPacket(true)

    try {
      const response = await fetch(
        'http://127.0.0.1:8000/firewall/evaluate',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            source_ip: sourceIP,
            destination_ip: destinationIP,
            protocol: packetProtocol,
            port: Number(packetPort),
          }),
        }
      )

      if (!response.ok) {
        throw new Error('Packet evaluation failed')
      }

      const result = await response.json()
      setPacketResult(result)
      setPacketMessage('Packet evaluated successfully!')
    } catch (error) {
      setPacketMessage(error.message)
    } finally {
      setCheckingPacket(false)
    }
  }

  // Analyze network traffic for anomalies
  const analyzeAnomaly = async (e) => {
    e.preventDefault()
    setAnomalyMessage('')
    setAnomalyResult(null)
    setCheckingAnomaly(true)

    try {
      const values = trafficData
        .split(',')
        .map((value) => Number(value.trim()))

      if (
        values.length === 0 ||
        values.some((value) => !Number.isFinite(value))
      ) {
        throw new Error('Enter valid comma-separated traffic values')
      }

      if (
        !Number.isFinite(Number(currentValue)) ||
        !Number.isFinite(Number(threshold)) ||
        Number(threshold) <= 0
      ) {
        throw new Error('Enter a valid current value and positive threshold')
      }

      const response = await fetch(
        'http://127.0.0.1:8000/anomaly/analyze',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            traffic_data: values,
            current_value: Number(currentValue),
            threshold: Number(threshold),
          }),
        }
      )

      if (!response.ok) {
        throw new Error('Anomaly analysis failed')
      }

      const result = await response.json()
      setAnomalyResult(result)
      setAnomalyMessage('Traffic analysis completed successfully!')
    } catch (error) {
      setAnomalyMessage(error.message)
    } finally {
      setCheckingAnomaly(false)
    }
  }

  // Fetch dashboard information from FastAPI
  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const [
          healthResponse,
          alertsResponse,
          eventsResponse,
          rulesResponse,
        ] = await Promise.all([
          fetch('http://127.0.0.1:8000/health'),
          fetch('http://127.0.0.1:8000/ids/alerts'),
          fetch('http://127.0.0.1:8000/ids/events'),
          fetch('http://127.0.0.1:8000/firewall/rules'),
        ])

        if (
          !healthResponse.ok ||
          !alertsResponse.ok ||
          !eventsResponse.ok ||
          !rulesResponse.ok
        ) {
          throw new Error('Backend request failed')
        }

        const health = await healthResponse.json()
        const alertsData = await alertsResponse.json()
        const eventsData = await eventsResponse.json()
        const rulesData = await rulesResponse.json()

        setBackendOnline(health.status === 'healthy')
        setAlerts(alertsData)
        setEvents(eventsData)
        setRules(rulesData)
      } catch (error) {
        console.error('Dashboard connection error:', error)
        setBackendOnline(false)
      } finally {
        setLoading(false)
      }
    }

    fetchDashboardData()

    const interval = setInterval(fetchDashboardData, 10000)

    return () => clearInterval(interval)
  }, [])

  // Dashboard calculations
  const highAlerts = alerts.filter(
    (alert) => alert.severity === 'HIGH'
  ).length

  const mediumAlerts = alerts.filter(
    (alert) => alert.severity === 'MEDIUM'
  ).length

  const formatTime = (timestamp) => {
    if (!timestamp) return 'N/A'
    return new Date(timestamp).toLocaleString()
  }

  return (
    <div className="dashboard">

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">S</div>
          <div>
            <h2>SENTINEL</h2>
            <span>Security Intelligence</span>
          </div>
        </div>

        <div className="sidebar-section">MAIN MENU</div>

        <nav className="navigation">
          <a href="#overview" className="nav-link active">
            <span>▦</span> Overview
          </a>

          <a href="#firewall" className="nav-link">
            <span>◈</span> Firewall Management
          </a>

          <a href="#intrusion" className="nav-link">
            <span>⌁</span> Intrusion Detection
          </a>

          <a href="#anomaly-analysis" className="nav-link">
            <span>⌁</span> Anomaly Detection
          </a>

          <a href="#events" className="nav-link">
            <span>▤</span> Security Events
          </a>
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className={`status-dot ${backendOnline ? 'online' : 'offline'}`}></span>
            {backendOnline ? 'System Connected' : 'Backend Offline'}
          </div>
          <p>SENTINEL v1.0.0</p>
          <p>Intrusion Detection & Firewall Simulator</p>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content" id="overview">

        {/* Header */}
        <header className="topbar">
          <div>
            <h1>Security Overview</h1>
            <p>Monitor your network security and system activity.</p>
          </div>

          <div className="topbar-right">
            <span className={`connection-badge ${backendOnline ? 'connected' : 'disconnected'}`}>
              <span className="status-dot"></span>
              {backendOnline ? 'Backend Online' : 'Backend Offline'}
            </span>
          </div>
        </header>

        {/* Welcome Banner */}
        <section className="welcome-banner">
          <div>
            <span className="eyebrow">NETWORK SECURITY CENTER</span>
            <h2>Welcome to SENTINEL</h2>
            <p>
              Your centralized security monitoring platform.
              Track threats, monitor firewall activity and detect anomalies.
            </p>
          </div>
          <div className="banner-symbol">⬡</div>
        </section>

        {/* Statistics */}
        <section className="stats-grid">

          <div className="stat-card">
            <div className="stat-heading">
              <span>Security Alerts</span>
              <span className="stat-icon red">⚠</span>
            </div>
            <h2>{loading ? '...' : alerts.length}</h2>
            <p>Total detected alerts</p>
          </div>

          <div className="stat-card">
            <div className="stat-heading">
              <span>High Severity</span>
              <span className="stat-icon red">!</span>
            </div>
            <h2>{loading ? '...' : highAlerts}</h2>
            <p>Critical security warnings</p>
          </div>

          <div className="stat-card">
            <div className="stat-heading">
              <span>Medium Severity</span>
              <span className="stat-icon yellow">◆</span>
            </div>
            <h2>{loading ? '...' : mediumAlerts}</h2>
            <p>Moderate security warnings</p>
          </div>

          <div className="stat-card">
            <div className="stat-heading">
              <span>Firewall Rules</span>
              <span className="stat-icon blue">◈</span>
            </div>
            <h2>{loading ? '...' : rules.length}</h2>
            <p>Configured firewall rules</p>
          </div>

        </section>

        {/* Security Alerts */}
        <section className="panel" id="intrusion">
          <div className="panel-header">
            <div>
              <h2>Recent Security Alerts</h2>
              <p>Alerts retrieved from the SENTINEL database</p>
            </div>
            <span className="live-label">LIVE DATA</span>
          </div>

          {loading ? (
            <p className="empty-message">Loading alerts...</p>
          ) : alerts.length === 0 ? (
            <p className="empty-message">No security alerts detected.</p>
          ) : (
            <div className="alert-list">
              {alerts.slice(0, 6).map((alert) => (
                <div className="alert-item" key={alert.id}>
                  <div className={`alert-indicator ${alert.severity?.toLowerCase()}`}></div>

                  <div className="alert-details">
                    <h3>{alert.type}</h3>
                    <p>{alert.message}</p>
                    <span>
                      {alert.source_ip} · {formatTime(alert.timestamp)}
                    </span>
                  </div>

                  <span className={`severity ${alert.severity?.toLowerCase()}`}>
                    {alert.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* System Health */}
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>System Health</h2>
              <p>Current status of security components</p>
            </div>
          </div>

          <div className="health-grid">
            <div className="health-item">
              <span>Firewall Engine</span>
              <strong className="health-active">● Active</strong>
            </div>

            <div className="health-item">
              <span>Intrusion Detection</span>
              <strong className="health-active">● Active</strong>
            </div>

            <div className="health-item" id="anomaly">
              <span>Anomaly Detection</span>
              <strong className="health-active">● Available</strong>
            </div>

            <div className="health-item">
              <span>Backend API</span>
              <strong className={backendOnline ? 'health-active' : 'health-inactive'}>
                ● {backendOnline ? 'Online' : 'Offline'}
              </strong>
            </div>
          </div>
        </section>

        {/* Firewall Rules */}
        <section className="panel" id="firewall">
          <div className="panel-header">
            <div>
              <h2>Firewall Rules</h2>
              <p>Configured rules from the backend database</p>
            </div>
          </div>

          <form onSubmit={addFirewallRule} className="firewall-form">
            <h3>Add New Firewall Rule</h3>

            <div className="form-grid">
              <input
                type="text"
                placeholder="Rule name"
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                required
              />

              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ANY">ANY</option>
              </select>

              <input
                type="number"
                placeholder="Port (optional)"
                min="1"
                max="65535"
                value={port}
                onChange={(e) => setPort(e.target.value)}
              />

              <select
                value={action}
                onChange={(e) => setAction(e.target.value)}
              >
                <option value="ALLOW">ALLOW</option>
                <option value="BLOCK">BLOCK</option>
              </select>

              <button type="submit" className="add-rule-button">
                + Add Rule
              </button>
            </div>

            {ruleMessage && (
              <p className="rule-message">{ruleMessage}</p>
            )}
          </form>

          {loading ? (
            <p className="empty-message">Loading firewall rules...</p>
          ) : rules.length === 0 ? (
            <p className="empty-message">No firewall rules configured.</p>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Rule Name</th>
                    <th>Protocol</th>
                    <th>Port</th>
                    <th>Action</th>
                    <th>Status</th>
                  </tr>
                </thead>

                <tbody>
                  {rules.map((rule) => (
                    <tr key={rule.id}>
                      <td>{rule.name}</td>
                      <td>{rule.protocol}</td>
                      <td>{rule.port ?? 'Any'}</td>
                      <td>
                        <span className={`severity ${rule.action?.toLowerCase()}`}>
                          {rule.action}
                        </span>
                      </td>
                      <td>{rule.enabled ? 'Enabled' : 'Disabled'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Packet Evaluation */}
        <section className="panel" id="packet-evaluation">
          <div className="panel-header">
            <div>
              <h2>Packet Evaluation</h2>
              <p>Test network packets against configured firewall rules</p>
            </div>
          </div>

          <form onSubmit={evaluatePacket} className="firewall-form">
            <h3>Evaluate Network Packet</h3>

            <div className="form-grid">
              <input
                type="text"
                placeholder="Source IP"
                value={sourceIP}
                onChange={(e) => setSourceIP(e.target.value)}
                required
              />

              <input
                type="text"
                placeholder="Destination IP"
                value={destinationIP}
                onChange={(e) => setDestinationIP(e.target.value)}
                required
              />

              <select
                value={packetProtocol}
                onChange={(e) => setPacketProtocol(e.target.value)}
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
              </select>

              <input
                type="number"
                placeholder="Port"
                min="1"
                max="65535"
                value={packetPort}
                onChange={(e) => setPacketPort(e.target.value)}
                required
              />

              <button
                type="submit"
                className="add-rule-button"
                disabled={checkingPacket}
              >
                {checkingPacket ? 'Checking...' : 'Evaluate Packet'}
              </button>
            </div>

            {packetMessage && (
              <p className="rule-message">{packetMessage}</p>
            )}

            {packetResult && (
              <div className="packet-result">
                <h3>
                  Decision:
                  <span className={packetResult.decision === 'BLOCK' ? 'packet-block' : 'packet-allow'}>
                    {' '}{packetResult.decision}
                  </span>
                </h3>
                <p>Matched Rule: {packetResult.matched_rule}</p>
                <p>{packetResult.message}</p>
              </div>
            )}
          </form>
        </section>

        {/* Anomaly Detection */}
        <section className="panel" id="anomaly-analysis">
          <div className="panel-header">
            <div>
              <h2>Anomaly Detection</h2>
              <p>Analyze network traffic and identify unusual activity</p>
            </div>
          </div>

          <form onSubmit={analyzeAnomaly} className="firewall-form">
            <h3>Analyze Network Traffic</h3>

            <div className="form-grid">
              <input
                type="text"
                placeholder="Traffic values (comma separated)"
                value={trafficData}
                onChange={(e) => setTrafficData(e.target.value)}
                required
              />

              <input
                type="number"
                placeholder="Current value"
                value={currentValue}
                onChange={(e) => setCurrentValue(e.target.value)}
                required
              />

              <input
                type="number"
                placeholder="Threshold"
                min="0.1"
                step="0.1"
                value={threshold}
                onChange={(e) => setThreshold(e.target.value)}
                required
              />

              <button
                type="submit"
                className="add-rule-button"
                disabled={checkingAnomaly}
              >
                {checkingAnomaly ? 'Analyzing...' : 'Analyze Traffic'}
              </button>
            </div>

            {anomalyMessage && (
              <p className="rule-message">{anomalyMessage}</p>
            )}

            {anomalyResult && (
              <div className="packet-result">
                <h3>
                  Status:
                  <span className={anomalyResult.is_anomaly ? 'packet-block' : 'packet-allow'}>
                    {' '}{anomalyResult.status}
                  </span>
                </h3>

                <p>Mean: {anomalyResult.mean}</p>
                <p>Standard Deviation: {anomalyResult.standard_deviation}</p>
                <p>Current Value: {anomalyResult.current_value}</p>
                <p>Z-Score: {anomalyResult.z_score}</p>
                <p>Anomaly Detected: {anomalyResult.is_anomaly ? 'Yes' : 'No'}</p>
              </div>
            )}
          </form>
        </section>

        {/* Security Events */}
        <section className="panel" id="events">
          <div className="panel-header">
            <div>
              <h2>Recent Security Events</h2>
              <p>Network events recorded by the intrusion detection system</p>
            </div>
          </div>

          {loading ? (
            <p className="empty-message">Loading events...</p>
          ) : events.length === 0 ? (
            <p className="empty-message">No security events recorded.</p>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Event Type</th>
                    <th>Port</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>

                <tbody>
                  {events.slice(0, 8).map((event) => (
                    <tr key={event.id}>
                      <td>{event.source_ip}</td>
                      <td>{event.event_type}</td>
                      <td>{event.port}</td>
                      <td>{formatTime(event.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <footer className="footer">
          SENTINEL — Intrusion Detection and Firewall Simulator
          <span> · </span>
          Data refreshes every 10 seconds
        </footer>

      </main>
    </div>
  )
}

export default App
