function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Set ${name} in the environment.`);
  return value;
}

function list(name) {
  const values = required(name).split(',').map(value => value.trim());
  if (values.some(value => !value)) throw new Error(`${name} must be a comma-separated list without empty entries.`);
  return values;
}

async function main() {
  const account = required('CF_ACCOUNT_ID');
  const token = required('CF_ACCESS_API_TOKEN');
  const applications = list('CF_ACCESS_APP_IDS');
  const loginMethods = list('CF_ACCESS_IDP_IDS');
  const domains = list('CF_ACCESS_EMAIL_DOMAINS');
  const include = domains.map(domain => ({ email_domain: { domain } }));
  async function api(path, body) {
    const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/access/apps/${path}`, {
      method: body ? 'PUT' : 'GET',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const result = await response.json();
    if (!response.ok || !result.success) {
      throw new Error(`Access API ${response.status}: ${JSON.stringify(result.errors)}`);
    }
    return result.result;
  }
  for (const id of applications) {
    const app = await api(id);
    const allows = app.policies.filter(policy => policy.decision === 'allow');
    if (!allows.length || app.policies.some(policy => policy.decision === 'bypass')) {
      throw new Error(`Review unexpected Access policies on ${app.name} before configuration.`);
    }
    for (const policy of allows) {
      await api(`${id}/policies/${policy.id}`, {
        name: 'Demo authorized email domains', decision: 'allow', include,
        exclude: [], require: [], precedence: policy.precedence,
      });
    }
    const settings = {
      name: app.name, type: app.type, destinations: app.destinations,
      allowed_idps: loginMethods, auto_redirect_to_identity: false,
      session_duration: app.session_duration,
    };
    if (app.domain) settings.domain = app.domain;
    await api(id, settings);
    const saved = await api(id);
    const actual = saved.policies.filter(policy => policy.decision === 'allow');
    if (actual.length !== allows.length || actual.some(policy =>
      JSON.stringify(policy.include) !== JSON.stringify(include) || policy.require.length || policy.exclude.length)) {
      throw new Error(`Access policy verification failed for ${app.name}.`);
    }
    console.log(`${app.name}: private; allowed email domains: ${domains.join(', ')}; configured identity providers only.`);
  }
  console.log('Existing agent Service Auth policies remain unchanged. No Bypass policy is present.');
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
