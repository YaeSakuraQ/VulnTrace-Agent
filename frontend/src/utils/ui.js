export function formatDateTime(value) {
  if (!value) {
    return 'n/a'
  }

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }

  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

export function prettifyStage(stage) {
  const labels = {
    validate_scope: '范围校验',
    assess: '上下文评估',
    observe: '观察',
    enumerate: '枚举',
    exploit: '利用',
    reflect: '反思',
    report: '报告生成',
    asset_discovery: '资产发现',
    service_fingerprint: '服务识别',
    web_probe: 'Web 探测',
    dir_enum: '目录枚举',
    ffuf_enum: '内容枚举',
    http_snapshot: '快照采集',
    vuln_verify: '漏洞验证',
    generate_report: '生成报告',
    finish: '完成',
    completed: '已完成',
  }

  return labels[stage] || stage || '未开始'
}

export function prettifyStatus(status) {
  const labels = {
    draft: '草稿',
    running: '运行中',
    paused: '已暂停',
    waiting_approval: '待审批',
    completed: '已完成',
    failed: '失败',
    stopped: '已终止',
  }

  return labels[status] || status || '未知'
}

export function statusTagType(status) {
  const map = {
    draft: 'default',
    running: 'info',
    paused: 'warning',
    waiting_approval: 'warning',
    completed: 'success',
    failed: 'error',
    stopped: 'error',
  }

  return map[status] || 'default'
}

export function riskTagType(risk) {
  const map = {
    low: 'info',
    medium: 'warning',
    high: 'error',
    confirmed: 'error',
    suspected: 'warning',
    approved: 'success',
    rejected: 'error',
    pending: 'warning',
  }

  return map[risk] || 'default'
}

export function decisionSourceLabel(source) {
  const labels = {
    llm: 'LLM 决策',
    heuristic: '启发式回退',
    approved_action: '审批恢复',
    mapper: '知识库候选',
    corpus: '知识库候选',
    corpus_reflection: '反思派生候选',
    learning: '已审核经验',
  }

  return labels[source] || source || '未知'
}

export function decisionSourceType(source) {
  const map = {
    llm: 'success',
    heuristic: 'warning',
    approved_action: 'info',
    mapper: 'info',
    corpus: 'info',
    corpus_reflection: 'warning',
    learning: 'success',
  }

  return map[source] || 'default'
}

export function failureClassLabel(failureClass) {
  const labels = {
    none: '无',
    parse_failure: '解析失败',
    blocked_request: '请求被拦截',
    target_not_found: '目标未命中',
    timeout: '超时',
    unexpected_redirect: '意外跳转',
    method_not_found: '方法不存在',
  }

  return labels[failureClass] || failureClass || '未知'
}

export function relativeArtifactPath(path) {
  if (!path) {
    return ''
  }

  const artifactsIdx = path.indexOf('artifacts/')
  if (artifactsIdx !== -1) {
    return path.slice(artifactsIdx)
  }

  return path
}

export function fileNameFromPath(path) {
  if (!path) {
    return ''
  }

  return path.split('/').pop()
}

export function countConfirmedFindings(findings = []) {
  return findings.filter((item) => String(item.confidence).toLowerCase() === 'confirmed').length
}
