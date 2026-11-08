// Simplified upstream HostsPage + product AppHeader. No remote/open/admin actions.
import { Alert, Button, Card, Empty, Input, Layout, message, Popconfirm, Space, Table, Tabs, Tag, Typography } from 'antd'
import { EditOutlined, GithubOutlined } from '@ant-design/icons'
import type { TableColumnsType } from 'antd'
import { useCallback, useEffect, useState } from 'react'
import { api, RequestError, type Device, type DeviceList } from './api'
import { ThemeToggle } from './ThemeToggle'
import { SiteFooter } from './SiteFooter'
const { Paragraph, Text, Title } = Typography
export function DevicesPage({ account, onSignedOut }: { account: string; onSignedOut: () => void }) {
  const [result, setResult] = useState<DeviceList>()
  const [loading, setLoading] = useState(true)
  const [loggingOut, setLoggingOut] = useState(false)
  const [error, setError] = useState('')
  const [updated, setUpdated] = useState('')
  const [renaming, setRenaming] = useState<Device>()
  const [newName, setNewName] = useState('')
  const [savingName, setSavingName] = useState(false)
  const [removingId, setRemovingId] = useState<string>()
  const [activeRole, setActiveRole] = useState<'host' | 'client'>('host')
  const [messageApi, contextHolder] = message.useMessage()
  const load = useCallback(async () => {
    setLoading(true); setError('')
    try { const data = await api<DeviceList>('/account/devices'); setResult(data); setUpdated(new Date().toLocaleTimeString('zh-CN')) }
    catch (err) { if (err instanceof RequestError && err.status === 401) onSignedOut(); else setError(err instanceof Error ? err.message : '加载失败，请重试。') }
    finally { setLoading(false) }
  }, [onSignedOut])
  async function submitRename() {
    if (!renaming) return
    const name = newName.trim()
    if (!name) { setError('设备名称不能为空'); return }
    setSavingName(true); setError('')
    try { await api(`/devices/${encodeURIComponent(renaming.deviceId)}/name`, { name }); setRenaming(undefined); await load() }
    catch (err) { setError(err instanceof Error ? err.message : '改名失败，请重试。') }
    finally { setSavingName(false) }
  }
  useEffect(() => { void load() }, [load])
  async function logout() {
    setLoggingOut(true)
    try { await api('/auth/logout', {}); onSignedOut() }
    catch (err) { setError(err instanceof Error ? err.message : '退出失败，请重试。') }
    finally { setLoggingOut(false) }
  }
  async function removeDevice(device: Device) {
    setRemovingId(device.deviceId)
    try {
      await api(`/devices/${encodeURIComponent(device.deviceId)}`, undefined, 'DELETE')
      messageApi.success(`已移除「${device.name}」`)
      await load()
    } catch (err) { messageApi.error(err instanceof Error ? err.message : '移除失败，请重试。') }
    finally { setRemovingId(undefined) }
  }
  const all = [...(result?.items ?? [])]
  const hosts = all.filter(d => d.role === 'host').sort((a, b) => Number(b.online) - Number(a.online))
  const clients = all.filter(d => d.role === 'client').sort((a, b) => Number(b.online) - Number(a.online))
  const devices = activeRole === 'host' ? hosts : clients
  const columns: TableColumnsType<Device> = [
    {
      title: '设备名称', dataIndex: 'name', key: 'name', render: (name: string, d) => renaming?.deviceId === d.deviceId
        ? <Space size={6}>
            <Input size="small" value={newName} autoFocus maxLength={80} style={{ width: 200 }} onChange={event => setNewName(event.target.value)} onPressEnter={() => void submitRename()} onKeyDown={event => { if (event.key === 'Escape') setRenaming(undefined) }} />
            <Button size="small" type="primary" loading={savingName} onClick={() => void submitRename()}>保存</Button>
            <Button size="small" onClick={() => setRenaming(undefined)}>取消</Button>
          </Space>
        : <Space size={10}><span className={`host-status-dot ${d.online ? 'is-online' : ''}`} /><Text strong className="selfhost-device-name">{name}</Text><Button type="text" size="small" icon={<EditOutlined />} aria-label="修改设备名称" onClick={() => { setRenaming(d); setNewName(d.name) }} /></Space>,
    },
    { title: '状态', dataIndex: 'online', key: 'online', render: (online: boolean) => online ? <Tag color="green">在线</Tag> : <Tag>离线</Tag> },
    { title: '系统', dataIndex: 'platform', key: 'platform', render: (platform: string) => ({ darwin: 'macOS', win32: 'Windows', linux: 'Linux', android: 'Android' })[platform] ?? platform },
    { title: '插件版本', dataIndex: 'clientVersion', key: 'clientVersion' },
    { title: 'Harness 版本', dataIndex: 'harnessVersion', key: 'harnessVersion', render: (value?: string) => value || '—' },
    {
      title: '操作', key: 'actions', width: 170,
      render: (_: unknown, d) => (
        <Space size={8}>
          <Popconfirm
            title="移除设备"
            description="移除后该设备立即断开且凭据失效；在同一设备上重新登录账号即可恢复授权。确认移除？"
            okText="移除" cancelText="取消" okButtonProps={{ danger: true }}
            onConfirm={() => void removeDevice(d)}
          >
            <Button size="small" danger loading={removingId === d.deviceId}>移除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]
  function deviceTable(items: Device[]) {
    return !error && !loading && !items.length
      ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无设备" />
      : <Table<Device> rowKey="deviceId" columns={columns} dataSource={items} loading={loading} pagination={false} scroll={{ x: 'max-content' }} />
  }
  return <>
    {contextHolder}
    <Layout.Header className="topbar product-topbar"><div className="topbar-inner"><div className="topbar-brand-group is-product"><a className="topbar-brand" href="/" aria-label="返回首页"><img className="topbar-brand-mark" src="/brand-whale.webp" alt="" width="40" height="40" /><span className="topbar-brand-copy"><Title level={3}>DeepSeek Harness Remote</Title><small>安全远程访问</small></span></a></div><div className="topbar-actions"><a className="topbar-github-link product-github-link" href="https://github.com/liguobao/ds-harness-remote" target="_blank" rel="noreferrer" aria-label="GitHub"><GithubOutlined /> GitHub</a><ThemeToggle /><Button type="text" loading={loggingOut} onClick={() => void logout()}>退出登录</Button></div></div></Layout.Header>
    <Layout.Content className="product-content selfhost-content" id="main-content">
      <div className="app-area"><div className="workspace-view"><div className="hosts-page">
        <header className="workspace-page-header"><div><Title level={2}>我的设备</Title><Paragraph className="selfhost-account">{account}</Paragraph></div><Space className="workspace-page-actions" wrap><Button onClick={() => void load()} loading={loading}>刷新</Button></Space></header>
        {error && <Alert className="selfhost-error" type="error" showIcon message={error} />}
        <Card className="page-card selfhost-connection" title="服务地址"><Paragraph><Text code className="selfhost-address">{result?.serverUrl ?? '加载中…'}</Text></Paragraph><Paragraph>主控端和被控端使用此地址。</Paragraph></Card>
        <Card className="page-card hosts-list-card" title="设备状态" extra={result ? <Text type="secondary">{devices.filter(d => d.online).length} / {devices.length} 台在线</Text> : undefined}>
          <Tabs
            activeKey={activeRole}
            onChange={key => setActiveRole(key as 'host' | 'client')}
            items={[
              { key: 'host', label: <span>被控端（{hosts.length}）</span>, children: deviceTable(hosts) },
              { key: 'client', label: <span>主控端（{clients.length}）</span>, children: deviceTable(clients) },
            ]}
          />
        </Card>
        {updated && <Paragraph className="selfhost-caption" type="secondary">更新于 {updated}</Paragraph>}
      </div></div></div>
    </Layout.Content><SiteFooter />
  </>
}
