export const authorize = async (page: Page) => {
  await page.goto('http://localhost:65432/');
  // If we are logged in, return early.
  const sessionState = await page.locator('#sessionState').textContent();
  if (sessionState === 'loggedin') {
    return;
  }
  if (sessionState !== 'start') {
    throw new Error(`Invalid session state [${sessionState}]`);
  }
  await page.locator('#login_button').click();

  await page.fill('#username', 'user1');
  await page.fill('#password', 'testuser123');
  await Promise.all([page.waitForResponse('**/token'), page.click('#kc-login')]);
};

export const loadFile = async (page: Page, path: string) => {
  await page.locator('#fileSelector').setInputFiles(path);
};
