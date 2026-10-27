export async function postJson(path, body, timeout = 15_000) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok)
      throw new Error(
        data.error || 'The request could not be completed. Please try again.',
      );
    return data;
  } catch (error) {
    if (error.name === 'AbortError')
      throw new Error('The request timed out. Please try again.');
    if (error.message === 'Failed to fetch')
      throw new Error('Could not reach the scanner. Please try again.');
    throw error;
  } finally {
    window.clearTimeout(timer);
  }
}
