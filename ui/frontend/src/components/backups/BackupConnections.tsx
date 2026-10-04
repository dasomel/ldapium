import { useState } from 'react'
import { backups, type BackupConnection, type BackupView } from '@/lib/backups'
import { useLanguage } from '@/context/LanguageContext'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const empty = (): BackupConnection => ({ id: '', name: '', type: 's3', host: '', port: 22, user: '', endpoint: '', region: 'us-east-1', bucket: '', prefix: 'ldapium-backups', known_hosts: '', allow_plaintext: false, password: '', access_key: '', secret_key: '' })
export function BackupConnections({ view, locked, onSaved }: { view: BackupView; locked: boolean; onSaved: (view: BackupView) => void }) {
  const { language } = useLanguage()
  const t = (ko: string, en: string) => language === 'ko' ? ko : en
  const [draft, setDraft] = useState<BackupConnection | null>(null)
  const [editing, setEditing] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const managed = view.connections ?? []
  const disabled = locked || busy || view.running
  function edit(c?: BackupConnection) { setDraft(c ? { ...c, password: '', access_key: '', secret_key: '' } : empty()); setEditing(!!c); setError(''); setMessage('') }
  async function save() {
    if (!draft) return
    setBusy(true); setError('')
    try { onSaved(await backups.saveConnection(draft, view.policies.revision)); setDraft(null); setMessage(t('저장했습니다. 백업 정책에서 저장소를 선택하세요. 연결 검증은 백업 실행 시 수행합니다.', 'Saved. Select the destination in a backup policy. Connectivity is verified when the backup runs.')) }
    catch (e) { setError((e as Error).message) }
    finally { setBusy(false) }
  }
  async function remove(id: string) {
    setBusy(true); setError('')
    try { onSaved(await backups.deleteConnection(id, view.policies.revision)); if (draft?.id === id) setDraft(null) }
    catch (e) { setError((e as Error).message) }
    finally { setBusy(false) }
  }
  function field(key: keyof BackupConnection, label: string, type = 'text', placeholder = '') {
    return <label className="space-y-1 text-sm" key={key}>{label}<Input type={type} value={String(draft?.[key] ?? '')} placeholder={placeholder} autoComplete={type === 'password' ? 'new-password' : 'off'} disabled={disabled || (key === 'id' && editing)} onChange={e => setDraft(previous => previous ? { ...previous, [key]: key === 'port' ? Number(e.target.value) : e.target.value } : previous)} /></label>
  }
  return <Card>
    <CardHeader><div className="flex flex-wrap items-center justify-between gap-2"><CardTitle>{t('외부 저장소 연결 설정', 'Remote destination settings')}</CardTitle><Button variant="outline" disabled={disabled} onClick={() => edit()}>{t('저장소 추가', 'Add destination')}</Button></div></CardHeader>
    <CardContent className="space-y-4">
      <p className="text-sm text-muted-foreground">{t('S3·FTP·FTPS·SSH/SFTP를 등록하고 데이터·로그 정책에서 선택합니다. 인증정보는 비공개 저장하며 다시 표시하지 않습니다. 수정 시 빈칸은 기존 값을 유지합니다.', 'Register S3, FTP, FTPS or SSH/SFTP and select it in data/log policies. Credentials are stored privately and never returned. Blank credential edits retain existing values.')}</p>
      {locked && <p className="text-sm text-accent">{t('변경한 백업 정책을 먼저 저장하세요.', 'Save changed backup policies first.')}</p>}
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      {message && <p role="status" className="text-sm">{message}</p>}
      <div className="space-y-2">{view.destinations.filter(d => d.type !== 'local').map(d => {
        const c = managed.find(c => c.id === d.id)
        const selected = view.policies.data.destinations.includes(d.id) || view.policies.logs.destinations.includes(d.id)
        return <div key={d.id} className="flex flex-wrap items-center justify-between gap-2 rounded-console border p-3 text-sm">
          <div className="min-w-0 break-all"><strong>{d.name}</strong> · {d.type.toUpperCase()}<div className="text-xs text-muted-foreground">{c ? `${c.type === 's3' ? `${c.endpoint || 'AWS S3'} / ${c.bucket}` : `${c.host}:${c.port}`} / ${c.prefix}` : t('운영자 등록 · 서버 설정에서 관리', 'Operator registered · managed in server configuration')}</div>{c && <span className="text-xs">{c.credentials_set ? t('인증정보 저장됨', 'Credentials stored') : t('인증정보 필요', 'Credentials required')}</span>}</div>
          {c && <div className="flex gap-2"><Button variant="outline" size="sm" disabled={disabled} onClick={() => edit(c)}>{t('수정', 'Edit')}</Button><Button variant="outline" size="sm" disabled={disabled || selected} title={selected ? t('정책에서 선택을 해제하고 저장하세요.', 'Unselect and save policies first.') : ''} onClick={() => void remove(c.id)}>{t('삭제', 'Remove')}</Button></div>}
        </div>
      })}</div>
      {!managed.length && <p className="text-sm text-muted-foreground">{t('UI에서 등록한 외부 저장소가 없습니다. 저장소 추가에서 연결을 설정하세요.', 'No UI-managed destination yet. Use Add destination to configure a connection.')}</p>}
      {draft && <form className="space-y-4 rounded-console border p-4" onSubmit={e => { e.preventDefault(); void save() }}>
        <h3 className="font-medium">{editing ? t('연결 수정', 'Edit connection') : t('연결 추가', 'Add connection')}</h3>
        <div className="grid gap-3 sm:grid-cols-2">
          {field('id', t('저장소 ID', 'Destination ID'), 'text', 's3-primary')}{field('name', t('표시 이름', 'Display name'))}
          <label className="space-y-1 text-sm">{t('연결 방식', 'Transport')}<select aria-label={t('연결 방식', 'Transport')} className="h-9 w-full rounded-md border bg-background px-3" value={draft.type} disabled={disabled || editing} onChange={e => setDraft({ ...empty(), id: draft.id, name: draft.name, type: e.target.value, port: e.target.value === 'sftp' ? 22 : 21 })}>{['s3', 'ftp', 'ftps', 'sftp'].map(type => <option key={type} value={type}>{type === 'sftp' ? 'SSH / SFTP' : type.toUpperCase()}</option>)}</select></label>
          {field('prefix', t('저장 경로 접두사', 'Archive prefix'))}
          {draft.type === 's3' ? <>{field('endpoint', t('S3 엔드포인트 (HTTPS, AWS는 빈칸)', 'S3 endpoint (HTTPS, blank for AWS)'), 'url', 'https://s3.example.org')}{field('region', t('리전', 'Region'))}{field('bucket', t('버킷', 'Bucket'))}{field('access_key', t('액세스 키', 'Access key'), 'password', editing ? t('빈칸이면 유지', 'Blank to retain') : '')}{field('secret_key', t('시크릿 키', 'Secret key'), 'password', editing ? t('빈칸이면 유지', 'Blank to retain') : '')}</> : <>{field('host', t('서버 주소', 'Host'))}{field('port', t('포트', 'Port'), 'number')}{field('user', t('사용자', 'Username'))}{field('password', t('비밀번호', 'Password'), 'password', editing ? t('빈칸이면 유지', 'Blank to retain') : '')}</>}
        </div>
        {draft.type === 'sftp' && <label className="block space-y-1 text-sm">{t('SSH 서버 호스트 키 (known_hosts)', 'SSH server host keys (known_hosts)')}<textarea aria-label={t('SSH 서버 호스트 키 (known_hosts)', 'SSH server host keys (known_hosts)')} className="min-h-24 w-full rounded-md border bg-background p-2 font-mono text-xs" value={draft.known_hosts} disabled={disabled} placeholder="[host]:2222 ssh-ed25519 AAAA…" onChange={e => setDraft({ ...draft, known_hosts: e.target.value })} /><span className="text-xs text-muted-foreground">{t('서버 운영자에게 확인한 키를 입력하세요. 불일치 시 연결을 거부합니다.', 'Enter keys verified with the server operator. Mismatched keys reject the connection.')}</span></label>}
        {draft.type === 'ftp' && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={draft.allow_plaintext} disabled={disabled} onChange={e => setDraft({ ...draft, allow_plaintext: e.target.checked })} />{t('평문 FTP 사용 허용 (인증정보·데이터 암호화 없음)', 'Allow plaintext FTP (credentials and data are unencrypted)')}</label>}
        {draft.type === 'ftps' && <p className="text-xs text-muted-foreground">{t('명시적 TLS와 서버 인증서 검증을 사용합니다.', 'Uses explicit TLS with server certificate verification.')}</p>}
        <div className="flex gap-2"><Button type="submit" disabled={disabled}>{t('연결 저장', 'Save connection')}</Button><Button type="button" variant="outline" disabled={busy} onClick={() => setDraft(null)}>{t('취소', 'Cancel')}</Button></div>
      </form>}
    </CardContent>
  </Card>
}
