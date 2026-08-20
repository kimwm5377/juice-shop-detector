(function () {
  var mouseMoveCount = 0;
  var scrollCount = 0;
  var domEventTypes = new Set();
  var TRACKED_EVENTS = [
    "click",
    "keydown",
    "keyup",
    "focus",
    "blur",
    "touchstart",
    "submit",
    "input",
  ];

  window.addEventListener("mousemove", function () {
    mouseMoveCount++;
  }, { passive: true });

  window.addEventListener("scroll", function () {
    scrollCount++;
  }, { passive: true });

  TRACKED_EVENTS.forEach(function (evt) {
    window.addEventListener(evt, function () {
      domEventTypes.add(evt);
    }, { passive: true, capture: true });
  });

  function send(isFinal) {
    var payload = {
      mouseMoveCount: mouseMoveCount,
      scrollCount: scrollCount,
      domEventTypes: Array.from(domEventTypes),
      pageLoad: true,
      url: window.location.pathname,
    };
    // 누적치는 리셋하고 다음 구간을 다시 센다 (서버에서 합산)
    mouseMoveCount = 0;
    scrollCount = 0;
    domEventTypes = new Set();

    var body = JSON.stringify(payload);
    if (navigator.sendBeacon) {
      navigator.sendBeacon(
        "/__detection/telemetry",
        new Blob([body], { type: "application/json" })
      );
    } else {
      fetch("/__detection/telemetry", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body,
        keepalive: true,
      }).catch(function () {});
    }
  }

  // 5초마다 주기적으로 전송 + 페이지 이탈 시 마지막 전송
  setInterval(function () { send(false); }, 5000);
  window.addEventListener("beforeunload", function () { send(true); });
})();
