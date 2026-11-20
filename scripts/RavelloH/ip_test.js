/**
 * 节点 IP 风险检测脚本
 * 作者：https://github.com/Roddy-D
 * 转写：https://github.com/RavelloH ，Quantumult X 兼容版
 *
 * 功能：
 *   检测节点出口 IP 纯净度，综合 IPPure/ipapi.is/IP2Location/DB-IP/Scamalytics/ipregistry 多家风控评分
 *
 * 配置 (Quantumult X):
 *   [task_local]
 *   event-interaction https://gist.github.com/RavelloH/d4152389cd810a402b641a625ce83857/raw/ip_test.js, tag=IP风险检测, img-url=shield.checkerboard.system, enabled=true
 *
 * 使用：长按节点 → 执行脚本
 */

const IP_API = "http://ip-api.com/json?lang=zh-CN";
const IPPURE_URL = "https://my.ippure.com/v1/info";
const IPAPI_IS_URL = "https://api.ipapi.is/";
const TIMEOUT = 8000;

function run() {
  const tag = $environment.params;
  if (!tag) return done("未获取到节点名称");

  var opts = { policy: tag };

  // 通过节点代理获取出口 IP
  $task.fetch({ url: IP_API, opts: opts, timeout: TIMEOUT })
    .then(function(r) {
      var d = JSON.parse(r.body);
      if (!d.query) return done("获取节点 IP 失败");
      startChecks(tag, opts, d);
    })
    .catch(function() {
      // 回退到 ipapi.is 直连
      $task.fetch({ url: IPAPI_IS_URL, timeout: TIMEOUT })
        .then(function(r2) {
          var d2 = JSON.parse(r2.body);
          if (d2 && d2.ip) {
            startChecks(tag, opts, { query: d2.ip, country: d2.location ? d2.location.country : "", regionName: "", city: d2.location ? d2.location.city : "", isp: (d2.asn || {}).org || "" });
          } else {
            return done("获取节点 IP 失败");
          }
        })
        .catch(function() { return done("获取节点 IP 失败"); });
    });
}

function startChecks(tag, opts, ipInfo) {
  var ip = ipInfo.query;

  var promises = [
    // IPPure
    $task.fetch({ url: IPPURE_URL, opts: opts, timeout: TIMEOUT })
      .then(function(r) { return { key: "ippure", data: JSON.parse(r.body) }; })
      .catch(function() { return { key: "ippure", data: null }; }),

    // ipapi.is
    $task.fetch({ url: IPAPI_IS_URL + "?q=" + encodeURIComponent(ip), opts: opts, timeout: TIMEOUT })
      .then(function(r) { return { key: "ipapi", data: JSON.parse(r.body) }; })
      .catch(function() { return { key: "ipapi", data: null }; }),

    // IP2Location.io
    $task.fetch({ url: "https://www.ip2location.io/" + encodeURIComponent(ip), opts: opts, headers: { "User-Agent": "Mozilla/5.0" }, timeout: TIMEOUT })
      .then(function(r) { return { key: "ip2loc", data: parseIp2location(r.body) }; })
      .catch(function() { return { key: "ip2loc", data: null }; }),

    // DB-IP
    $task.fetch({ url: "https://db-ip.com/" + encodeURIComponent(ip), opts: opts, timeout: TIMEOUT })
      .then(function(r) { return { key: "dbip", data: r.body }; })
      .catch(function() { return { key: "dbip", data: null }; }),

    // Scamalytics
    $task.fetch({ url: "https://scamalytics.com/ip/" + encodeURIComponent(ip), opts: opts, timeout: TIMEOUT })
      .then(function(r) { return { key: "scam", data: r.body }; })
      .catch(function() { return { key: "scam", data: null }; }),

    // ipregistry
    $task.fetch({ url: "https://ipregistry.co/" + encodeURIComponent(ip), opts: opts, headers: { "User-Agent": "Mozilla/5.0" }, timeout: TIMEOUT })
      .then(function(r) { return { key: "ipreg", data: parseIpregistry(r.body) }; })
      .catch(function() { return { key: "ipreg", data: null }; })
  ];

  Promise.allSettled(promises).then(function(results) {
    var data = {};
    for (var i = 0; i < results.length; i++) {
      if (results[i].status === "fulfilled") {
        var v = results[i].value;
        data[v.key] = v.data;
      }
    }
    render(tag, ipInfo, data);
  });
}

function parseIp2location(html) {
  if (!html) return null;
  var s = String(html);
  var m;

  m = s.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*\(([A-Z]+)\)/i);
  if (!m) m = s.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*([A-Z]+(?:\/[A-Z]+)?)\s*</i);
  var usageType = m ? m[1] : null;

  m = s.match(/Fraud\s*Score<\/label>\s*<p[^>]*>\s*(\d+)/i);
  var fraudScore = m ? parseInt(m[1]) : null;

  m = s.match(/>Proxy<\/label>\s*<p[^>]*>[^<]*<i[^>]*><\/i>\s*(Yes|No)/i);
  var isProxy = m ? m[1].toLowerCase() === "yes" : false;

  m = s.match(/Proxy\s*Type<\/label>\s*<p[^>]*>\s*([^<]+)/i);
  var proxyType = m ? m[1].trim() : "-";

  m = s.match(/>Threat<\/label>\s*<p[^>]*>\s*([^<]+)/i);
  var threat = m ? m[1].trim() : "-";

  return { usageType: usageType, fraudScore: fraudScore, isProxy: isProxy, proxyType: proxyType, threat: threat };
}

function parseIpregistry(html) {
  if (!html) return null;
  function flag(name, s) {
    var re = new RegExp(name + "</span>[\\s\\S]{0,300}?<div class=\"(?:positive|negative)\">[\\s\\S]{0,800}?(Yes|No)</div>", "i");
    var m = s.match(re);
    return m ? m[1].trim().toLowerCase() === "yes" : null;
  }
  var s = String(html);
  var fields = ["Abuser","Attacker","Bogon","Cloud Provider","Proxy","Relay","Tor","VPN","Anonymous","Threat"];
  var r = {};
  var allNull = true;
  for (var i = 0; i < fields.length; i++) {
    var key = fields[i].toLowerCase().replace(" ", "_");
    r[key] = flag(fields[i], s);
    if (r[key] !== null) allNull = false;
    if (key === "cloud_provider") r["is_cloud_provider"] = r[key];
    if (key === "cloud provider") r["is_cloud_provider"] = r[key];
  }
  // normalize keys
  r.is_proxy = r.proxy;
  r.is_tor = r.tor;
  r.is_vpn = r.vpn;
  r.is_abuser = r.abuser;
  r.is_attacker = r.attacker;
  r.is_bogon = r.bogon;
  r.is_anonymous = r.anonymous;
  r.is_threat = r.threat;
  r.is_relay = r.relay;
  if (allNull) return null;
  return r;
}

function gradeIppure(data) {
  if (!data) return { text: "IPPure：获取失败", sev: 2 };
  var s = data.fraudScore;
  if (s === null || s === undefined) return { text: "IPPure：获取失败", sev: 2 };
  if (s >= 80) return { text: "🛑 极高风险 (" + s + ")", sev: 4 };
  if (s >= 70) return { text: "⚠️ 高风险 (" + s + ")", sev: 3 };
  if (s >= 40) return { text: "🔶 中等风险 (" + s + ")", sev: 1 };
  return { text: "✅ 低风险 (" + s + ")", sev: 0 };
}

function gradeIpapi(data) {
  if (!data || !data.company) return { text: "ipapi.is：获取失败", sev: 2 };
  var s = data.company.abuser_score;
  if (!s) return { text: "ipapi.is：无评分", sev: 2 };
  var m = String(s).match(/([0-9.]+)\s*\(([^)]+)\)/);
  if (!m) return { text: "ipapi.is：" + s, sev: 2 };
  var pct = (parseFloat(m[1]) * 100).toFixed(1) + "%";
  var level = m[2];
  var sevMap = { "Very Low": 0, "Low": 0, "Elevated": 2, "High": 3, "Very High": 4 };
  var sev = sevMap[level] || 2;
  var label = sev >= 4 ? "🛑 极高风险" : sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "✅ 低风险";
  return { text: label + " (" + pct + ", " + level + ")", sev: sev };
}

function gradeIp2location(data) {
  if (!data) return { text: null, sev: -1 };
  var s = data.fraudScore;
  if (s === null) return { text: null, sev: -1 };
  if (s >= 66) return { text: "⚠️ 高风险 (" + s + ")", sev: 3 };
  if (s >= 33) return { text: "🔶 中风险 (" + s + ")", sev: 1 };
  return { text: "✅ 低风险 (" + s + ")", sev: 0 };
}

function gradeDbip(html) {
  if (!html) return { text: "DB-IP：获取失败", sev: 2 };
  var m = String(html).match(/Estimated threat level for this IP address is\s*<span[^>]*>\s*([^<\s]+)\s*</i);
  if (!m) return { text: "DB-IP：获取失败", sev: 2 };
  var t = m[1].toLowerCase();
  if (t === "high") return { text: "⚠️ 高风险 (high)", sev: 3 };
  if (t === "medium") return { text: "🔶 中风险 (medium)", sev: 1 };
  if (t === "low") return { text: "✅ 低风险 (low)", sev: 0 };
  return { text: "DB-IP：" + t, sev: 2 };
}

function gradeScamalytics(html) {
  if (!html) return { text: "Scamalytics：获取失败", sev: 2 };
  var m = String(html).match(/Fraud\s*Score[:\s]*(\d+)/i)
    || String(html).match(/class="score"[^>]*>(\d+)/i)
    || String(html).match(/"score"\s*:\s*(\d+)/i);
  if (!m) return { text: "Scamalytics：获取失败", sev: 2 };
  var s = parseInt(m[1]);
  if (s >= 90) return { text: "🛑 极高风险 (" + s + ")", sev: 4 };
  if (s >= 60) return { text: "⚠️ 高风险 (" + s + ")", sev: 3 };
  if (s >= 20) return { text: "🔶 中风险 (" + s + ")", sev: 1 };
  return { text: "✅ 低风险 (" + s + ")", sev: 0 };
}

function gradeIpregistry(data) {
  if (!data) return { text: "ipregistry：获取失败", sev: 2 };
  var items = [];
  if (data.is_proxy === true) items.push("Proxy");
  if (data.is_tor === true) items.push("Tor");
  if (data.is_vpn === true) items.push("VPN");
  if (data.is_cloud_provider === true) items.push("Hosting");
  if (data.is_abuser === true) items.push("Abuser");
  if (items.length === 0) return { text: "✅ 低风险（无标记）", sev: 0 };
  var sev = items.indexOf("Tor") !== -1 ? 3 : items.indexOf("Abuser") !== -1 ? 3 : items.length >= 2 ? 2 : 1;
  var label = sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "🔶 有标记";
  return { text: label + " (" + items.join("/") + ")", sev: sev };
}

function usageTypeText(ut) {
  if (!ut) return null;
  var map = { "DCH": "🏢 数据中心", "WEB": "🏢 数据中心", "SES": "🏢 数据中心", "CDN": "🌐 CDN",
              "MOB": "📱 蜂窝移动", "ISP": "🏠 家庭宽带", "COM": "🏬 商业宽带",
              "EDU": "🎓 教育网络", "GOV": "🏛️ 政府网络", "MIL": "🎖️ 军用网络", "ORG": "🏢 组织机构", "RES": "🏠 住宅网络" };
  var parts = String(ut).toUpperCase().split("/");
  var seen = {}, descs = [];
  for (var i = 0; i < parts.length; i++) {
    var d = map[parts[i]] || null;
    if (d && !seen[d]) { seen[d] = true; descs.push(d); }
  }
  if (descs.length === 0) descs.push("❓ " + ut);
  return descs.join(" / ");
}

function getFlag(cc) {
  if (!cc || cc.length !== 2) return "🌍";
  if (cc === "TW") cc = "CN";
  var cp = cc.toUpperCase().split("").map(function(c) { return 127397 + c.charCodeAt(0); });
  return String.fromCodePoint.apply(null, cp);
}

function render(tag, ipInfo, data) {
  var ip = ipInfo.query;
  var parts = [];

  // 节点代理
  var nodeStr = '<span style="font-weight: bold">节点代理</span>: ✅ 正常';
  nodeStr += '<br/>' + '<span style="font-weight: bold">IP</span>: ' + ip;
  nodeStr += '<br/>' + '<span style="font-weight: bold">位置</span>: ' + getFlag(ipInfo.countryCode || ipInfo.country) + ' ' + [ipInfo.country, ipInfo.regionName, ipInfo.city].filter(Boolean).join(" - ");
  nodeStr += '<br/>' + '<span style="font-weight: bold">ISP</span>: ' + (ipInfo.isp || "未知");
  parts.push(nodeStr);

  // IP类型 (IP2Location)
  var ip2loc = data.ip2loc;
  if (ip2loc && ip2loc.usageType) {
    var typeText = usageTypeText(ip2loc.usageType);
    if (typeText) {
      parts.push('<span style="font-weight: bold">IP 类型</span>: ' + typeText + " (IP2Location)");
    }
  }

  // 多源评分
  var grades = [],
      labels = [];
  var g;

  g = gradeIppure(data.ippure);
  if (g.text) { grades.push(g); labels.push("IPPure:          " + g.text); }

  g = gradeIpapi(data.ipapi);
  if (g.text) { grades.push(g); labels.push("ipapi.is:        " + g.text); }

  g = gradeIp2location(ip2loc);
  if (g.text) { grades.push(g); labels.push("IP2Location.io:  " + g.text); }

  g = gradeScamalytics(data.scam);
  if (g.text) { grades.push(g); labels.push("Scamalytics:     " + g.text); }

  g = gradeDbip(data.dbip);
  if (g.text) { grades.push(g); labels.push("DB-IP:           " + g.text); }

  g = gradeIpregistry(data.ipreg);
  if (g.text) { grades.push(g); labels.push("ipregistry:      " + g.text); }

  var riskStr = '<span style="font-weight: bold">📊 IP 风险评估</span>';
  for (var i = 0; i < labels.length; i++) {
    riskStr += '<br/><code style="font-family: Menlo, Monaco, monospace; font-size: 13px">' + labels[i] + '</code>';
  }
  parts.push(riskStr);

  // 诊断结论
  var maxSev = 0;
  for (var j = 0; j < grades.length; j++) {
    maxSev = Math.max(maxSev, grades[j].sev || 0);
  }

  parts.push('<span style="font-weight: bold">📋 诊断结论</span>');
  if (maxSev >= 4) {
    parts.push('🛑 <b>极高风险</b> — 该 IP 被多家风控服务标记，流媒体/网站访问可能受限');
  } else if (maxSev >= 3) {
    parts.push('⚠️ <b>高风险</b> — 该 IP 存在较明显风控标记，建议更换节点');
  } else if (maxSev >= 2) {
    parts.push('🔶 <b>中等风险</b> — 部分服务有标记，一般使用无碍');
  } else if (maxSev >= 1) {
    parts.push('🔶 <b>低度风险</b> — 仅个别服务有轻微标记');
  } else {
    parts.push('✅ <b>IP 纯净度良好</b> — 未被主要风控服务标记');
  }

  // 节点名称
  parts.push('<span style="font-weight: bold">节点</span>: <span style="color: #467fcf">' + (tag || "当前节点") + '</span>');

  var html = parts.join('<br/><br/>');

  $done({
    "title": "   🔍 节点 IP 风险检测",
    htmlMessage: '<div style="font-family: -apple-system; font-size: large">' + html + '</div>'
  });
}

function done(msg) {
  $done({
    "title": "   🔍 节点 IP 风险检测",
    htmlMessage: '<div style="font-family: -apple-system; font-size: large"><span style="font-weight: bold">🛑 ' + msg + '</span></div>'
  });
}

run();
