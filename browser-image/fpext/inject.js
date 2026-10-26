// Maskowanie fingerprintu - działa w świecie MAIN strony, na document_start, we wszystkich ramkach.
// Konfiguracja pochodzi z config.js (globalna zmienna usuwana zaraz po odczycie).
(function () {
  'use strict';
  const FP = self.__VMBR_FP__;
  try { delete self.__VMBR_FP__; } catch (e) { /* ignore */ }
  if (!FP || self.__vmbrApplied) return;
  Object.defineProperty(self, '__vmbrApplied', { value: true, enumerable: false });

  // ---- pomocnicze: funkcje wyglądające na natywne ------------------------------------
  const nativeToString = Function.prototype.toString;
  const fakeSrc = new WeakMap();
  const patchedToString = new Proxy(nativeToString, {
    apply(target, thisArg, args) {
      if (fakeSrc.has(thisArg)) return fakeSrc.get(thisArg);
      return Reflect.apply(target, thisArg, args);
    },
  });
  fakeSrc.set(patchedToString, 'function toString() { [native code] }');
  Object.defineProperty(Function.prototype, 'toString',
    { value: patchedToString, writable: true, configurable: true, enumerable: false });

  function mask(fn, name) {
    try { Object.defineProperty(fn, 'name', { value: name, configurable: true }); } catch (e) { /* ignore */ }
    fakeSrc.set(fn, 'function ' + name + '() { [native code] }');
    return fn;
  }

  function overrideGetter(obj, prop, value) {
    if (!obj) return;
    const d = Object.getOwnPropertyDescriptor(obj, prop);
    if (!d || !d.get) return;
    const getter = mask(function () { return typeof value === 'function' ? value.call(this) : value; }, 'get ' + prop);
    Object.defineProperty(obj, prop, { get: getter, set: d.set, enumerable: d.enumerable, configurable: true });
  }

  function wrapMethod(obj, prop, make) {
    if (!obj || typeof obj[prop] !== 'function') return;
    const orig = obj[prop];
    const wrapped = mask(make(orig), prop);
    Object.defineProperty(obj, prop,
      { value: wrapped, writable: true, configurable: true, enumerable: Object.getOwnPropertyDescriptor(obj, prop).enumerable });
  }

  // ---- deterministyczny szum (ten sam wynik przy każdym wywołaniu w profilu) -----------
  function hash32(seed, i) {
    let h = (seed ^ Math.imul(i + 1, 0x9e3779b1)) >>> 0;
    h = Math.imul(h ^ (h >>> 15), 0x85ebca6b) >>> 0;
    h = Math.imul(h ^ (h >>> 13), 0xc2b2ae35) >>> 0;
    return (h ^ (h >>> 16)) >>> 0;
  }
  function noisePixels(data, seed) {
    for (let i = 0; i < data.length; i += 4) {
      const h = hash32(seed, i >> 2);
      if ((h & 7) === 0) { data[i + (h >>> 3) % 3] ^= 1; }  // zmiana najmłodszego bitu jednego z kanałów RGB
    }
  }

  const major = (/Chrome\/(\d+)/.exec(navigator.userAgent) || [, '120'])[1];
  const ua = FP.uaTemplate.replace('%MAJOR%', major);

  // ---- navigator -----------------------------------------------------------------------
  const NavProto = Navigator.prototype;
  const langs = Object.freeze(FP.languages.slice());
  overrideGetter(NavProto, 'userAgent', ua);
  overrideGetter(NavProto, 'appVersion', ua.replace(/^Mozilla\//, ''));
  overrideGetter(NavProto, 'platform', FP.platform);
  overrideGetter(NavProto, 'language', langs[0]);
  overrideGetter(NavProto, 'languages', langs);
  overrideGetter(NavProto, 'hardwareConcurrency', FP.hardwareConcurrency);
  overrideGetter(NavProto, 'deviceMemory', FP.deviceMemory);
  overrideGetter(NavProto, 'maxTouchPoints', 0);
  overrideGetter(NavProto, 'webdriver', false);

  // ---- userAgentData (Client Hints po stronie JS) --------------------------------------
  if (typeof NavigatorUAData !== 'undefined') {
    const brands = [
      { brand: 'Chromium', version: major },
      { brand: 'Not.A/Brand', version: '24' },
      { brand: 'Google Chrome', version: major },
    ];
    overrideGetter(NavigatorUAData.prototype, 'brands', brands);
    overrideGetter(NavigatorUAData.prototype, 'mobile', false);
    overrideGetter(NavigatorUAData.prototype, 'platform', FP.chPlatform);
    wrapMethod(NavigatorUAData.prototype, 'getHighEntropyValues', function () {
      return function (hints) {
        const full = major + '.0.0.0';
        const all = {
          architecture: 'x86', bitness: '64', model: '', wow64: false,
          platformVersion: FP.chPlatformVersion, uaFullVersion: full,
          fullVersionList: brands.map((b) => ({ brand: b.brand, version: b.version === '24' ? '24.0.0.0' : full })),
          brands: brands, mobile: false, platform: FP.chPlatform,
        };
        const out = { brands: brands, mobile: false, platform: FP.chPlatform };
        (hints || []).forEach((h) => { if (h in all) out[h] = all[h]; });
        return Promise.resolve(out);
      };
    });
  }

  // ---- ekran ---------------------------------------------------------------------------
  if (typeof Screen !== 'undefined') {
    const s = FP.screen;
    ['width', 'height', 'availWidth', 'availHeight', 'colorDepth'].forEach((k) => overrideGetter(Screen.prototype, k, s[k]));
    overrideGetter(Screen.prototype, 'pixelDepth', s.colorDepth);
  }

  // ---- canvas --------------------------------------------------------------------------
  const MAX_PIXELS = 4096 * 4096;
  function noisyCopy(canvas) {
    const w = canvas.width, h = canvas.height;
    if (!w || !h || w * h > MAX_PIXELS) return null;
    const tmp = document.createElement('canvas');
    tmp.width = w; tmp.height = h;
    const ctx = tmp.getContext('2d');
    if (!ctx) return null;
    ctx.drawImage(canvas, 0, 0);
    const img = origGetImageData.call(ctx, 0, 0, w, h);
    noisePixels(img.data, FP.noise.canvas);
    ctx.putImageData(img, 0, 0);
    return tmp;
  }
  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  wrapMethod(CanvasRenderingContext2D.prototype, 'getImageData', function (orig) {
    return function () {
      const img = Reflect.apply(orig, this, arguments);
      try { noisePixels(img.data, FP.noise.canvas); } catch (e) { /* ignore */ }
      return img;
    };
  });
  ['toDataURL', 'toBlob'].forEach((m) => wrapMethod(HTMLCanvasElement.prototype, m, function (orig) {
    return function () {
      let src = this;
      try { src = noisyCopy(this) || this; } catch (e) { src = this; }
      return Reflect.apply(orig, src, arguments);
    };
  }));

  // ---- WebGL ---------------------------------------------------------------------------
  [self.WebGLRenderingContext, self.WebGL2RenderingContext].forEach((Ctx) => {
    if (!Ctx) return;
    wrapMethod(Ctx.prototype, 'getParameter', function (orig) {
      return function (p) {
        if (p === 0x9245) return FP.webgl.vendor;    // UNMASKED_VENDOR_WEBGL
        if (p === 0x9246) return FP.webgl.renderer;  // UNMASKED_RENDERER_WEBGL
        return Reflect.apply(orig, this, arguments);
      };
    });
    wrapMethod(Ctx.prototype, 'readPixels', function (orig) {
      return function () {
        const r = Reflect.apply(orig, this, arguments);
        const buf = arguments[6];
        if (buf instanceof Uint8Array || buf instanceof Uint8ClampedArray) noisePixels(buf, FP.noise.webgl);
        return r;
      };
    });
  });

  // ---- audio ---------------------------------------------------------------------------
  if (typeof AudioBuffer !== 'undefined') {
    const done = new WeakSet();
    wrapMethod(AudioBuffer.prototype, 'getChannelData', function (orig) {
      return function () {
        const data = Reflect.apply(orig, this, arguments);
        if (!done.has(data)) {
          done.add(data);
          for (let i = 0; i < data.length; i += 100) data[i] += ((hash32(FP.noise.audio, i) & 0xff) - 128) * 1e-7;
        }
        return data;
      };
    });
  }
  if (typeof AnalyserNode !== 'undefined') {
    ['getFloatFrequencyData', 'getFloatTimeDomainData'].forEach((m) => wrapMethod(AnalyserNode.prototype, m, function (orig) {
      return function (arr) {
        const r = Reflect.apply(orig, this, arguments);
        for (let i = 0; i < arr.length; i++) arr[i] += ((hash32(FP.noise.audio, i) & 0xff) - 128) * 1e-5;
        return r;
      };
    }));
  }

  // ---- urządzenia multimedialne (pusta lista to znak rozpoznawczy kontenera) ------------
  if (typeof MediaDevices !== 'undefined' && typeof MediaDeviceInfo !== 'undefined') {
    wrapMethod(MediaDevices.prototype, 'enumerateDevices', function (orig) {
      return function () {
        return Reflect.apply(orig, this, arguments).then((list) => {
          if (list && list.length) return list;
          const mk = (kind, n) => {
            const o = Object.create(MediaDeviceInfo.prototype);
            const id = hash32(FP.noise.devices, n).toString(16).padStart(8, '0').repeat(8);
            Object.defineProperties(o, {
              deviceId: { value: kind === 'audiooutput' ? 'default' : id, enumerable: true },
              kind: { value: kind, enumerable: true },
              label: { value: '', enumerable: true },
              groupId: { value: id.split('').reverse().join(''), enumerable: true },
            });
            return o;
          };
          return [mk('audioinput', 1), mk('videoinput', 2), mk('audiooutput', 3)];
        });
      };
    });
  }
})();
