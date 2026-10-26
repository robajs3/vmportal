// Spójność nagłówków HTTP z fingerprintem wstrzykiwanym do strony: Sec-CH-UA*.
importScripts('config.js');

(function () {
  const FP = self.__VMBR_FP__;
  if (!FP) return;
  const major = (/Chrome\/(\d+)/.exec(navigator.userAgent) || [, '120'])[1];
  const rules = [{
    id: 1,
    priority: 1,
    action: {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'sec-ch-ua', operation: 'set',
          value: `"Chromium";v="${major}", "Not.A/Brand";v="24", "Google Chrome";v="${major}"` },
        { header: 'sec-ch-ua-mobile', operation: 'set', value: '?0' },
        { header: 'sec-ch-ua-platform', operation: 'set', value: `"${FP.chPlatform}"` },
      ],
    },
    condition: {
      urlFilter: '|http',
      resourceTypes: ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object',
        'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'other'],
    },
  }];
  chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [1], addRules: rules });
})();
