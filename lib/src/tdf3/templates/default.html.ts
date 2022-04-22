import { escHtml, escJavaScript } from './escaper';

export default ({ manifest, payload, transferUrl, transferBaseUrl }) => `<html>
<head>
    <meta charset="UTF-8">
  </head>
  <body style="font-family: Arial; color: #2D323B; overflow: hidden; margin: 0; height: 100%; background-color: white;">
    <input id="data-input" type="hidden" value="${escHtml(payload)}">
    <input id="data-manifest" type="hidden" value="${escHtml(manifest)}">
    <iframe style="width:0;height:0;border:0; border:none;" src="${escHtml(transferUrl)}"></iframe>
    <div role="banner" style="background-color: #092356; color: white; height: 55px;">
      <img src="https://cdn.virtru.com/assets/virtru-logo-white-rgb.png"
           style="display: inline-block; padding: 18px 0 0 24px;"
           width="62px" height="19px" alt="Virtru logo" title="Virtru"/>
    </div>
   <div role="main" class="wrapper" style="padding-top: 107px; display: flex; flex-direction: row; max-width: 1200px;
          min-width: 800px; margin: 0 auto; min-height: calc(100vh - 230px); border-bottom: 1px solid #F3F5F7;">
      <div role="region">
        <img src="https://cdn.virtru.com/assets/request-access.png" style="display: inline-block;"
             width="387px" height="310px" alt="Request access image" title="Request access"/>
      </div>
      <div role="complementary" style="word-break: break-all; padding-right: 12px;">
        <h1 style="font-size: 1.5em;">Virtru Secure File</h1>
        <noscript style="font-weight: 100;">
          <span>
            To view this file, download and access it from your computer:
            <br />
            <br />
          </span>
          <div>
            1. <b>Go Back</b> to the file directory and <b>Right-click</b> on the file
          </div>
          <div>
            2. Select <b>Download</b>
          </div>
          <div>
            3. Once download is complete, <b>double-click</b> on the local file to open
          </div>
        </noscript>
        <div id="js-enabled-message" style="display: none;">
          <span>We are trying to send you to Secure Reader. If this does not work, please click the button below</span>
          <br />
          <button
            id="viewbutton"
            style="color: #fff!important; background: gray; padding: 10px 40px; border-radius: 25px; display: inline-block; border: none; font-size: 15px; width: 300px; margin-block-start: 1.1em;
    margin-block-end: 1.1em;"
            class="viewbutton"
            type="button"
          >
            View File in Secure Reader
          </button>
        </div>
      </div>
    </div>
    <div role="contentinfo" style="color: grey; text-align: center; padding-top: 25px; font-family: Arial;">
        <span style="padding: 25px; font-size: 13px;">© Copyright 2019 Virtru Corporation</span>
        <span style="padding: 25px; font-size: 13px;">Learn more at www.virtru.com</span>
    </div>
    <script type="text/javascript">
      var transferComplete = false;
      var data = document.getElementById('data-input').value;
      var manifest = JSON.parse(atob(document.getElementById('data-manifest').value));
      var redirectButton = document.getElementById('viewbutton');
      var ifr = document.querySelector('iframe');
      var otherWindow = ifr.contentWindow;

      document.getElementById('js-enabled-message').style.display = 'block';
      ifr.addEventListener("load", iframeLoaded, false);

      function iframeLoaded() {
        var channel = new MessageChannel();
        otherWindow.postMessage({
          type: 'tdf.html',
          data: data,
          policy: manifest.encryptionInformation.policy
        }, '${escJavaScript(transferBaseUrl)}', [channel.port2]);

        channel.port1.onmessage = handleMessage;

        function handleMessage(e) {
          let msg = e.data;
          if (msg.status === 'success') {
            transferComplete = true;
            redirectButton.style.background = '#4585ff';
            window.location.href = "${escJavaScript(transferUrl)}";
          }
        }
      }
      redirectButton.onclick = function(){
        if (transferComplete) {
          window.location.href = "${escJavaScript(transferUrl)}";
        }
      };
    </script>
  </body>
</html>`;
