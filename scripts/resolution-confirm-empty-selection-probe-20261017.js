(async () => {
  const path = '/trusted-human/resolution/api/package';
  const read = await fetch(path, {credentials: 'same-origin', cache: 'no-store', redirect: 'manual'});
  if (!read.ok) {
    console.log(JSON.stringify({phase: 'READ', status: read.status, type: read.type}));
    return;
  }
  const data = await read.json();
  if (!data.package || typeof data.package.snapshotHash !== 'string' ||
      typeof data.csrfToken !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(data.csrfHeader)) {
    console.log(JSON.stringify({phase: 'READ', code: 'UNEXPECTED_PACKAGE_SHAPE'}));
    return;
  }
  const response = await fetch(path + '/confirm', {
    method: 'POST', credentials: 'same-origin', redirect: 'manual',
    headers: {'Content-Type': 'application/json', [data.csrfHeader]: data.csrfToken},
    body: JSON.stringify({snapshotHash: data.package.snapshotHash, choices: []})
  });
  const raw = await response.text();
  let code = null;
  if (raw.length <= 8192) {
    try {
      const body = JSON.parse(raw);
      code = [body.code, body.detail, body.message].find(value =>
        typeof value === 'string' && /^[A-Z][A-Z0-9_]{1,159}$/.test(value)) || null;
    } catch (_) {}
  }
  console.log(JSON.stringify({phase: 'EMPTY_SELECTION_PROBE', status: response.status,
    type: response.type, code, submittedChoices: 0,
    contentType: response.headers.get('content-type')}));
})().catch(() => console.log(JSON.stringify({phase: 'PROBE', code: 'NETWORK_OR_REDIRECT_FAILURE'})));
