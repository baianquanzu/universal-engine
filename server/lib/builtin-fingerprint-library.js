export const fingerprintLibraryMeta = [
  {
    name: "FingerprintHub",
    repo: "https://github.com/0x727/FingerprintHub",
    note: "ObserverWard community fingerprint library, strong on Chinese web products and OA systems."
  },
  {
    name: "wappalyzergo",
    repo: "https://github.com/projectdiscovery/wappalyzergo",
    note: "Wappalyzer-compatible technology detection data, strong on common web frameworks."
  },
  {
    name: "EHole",
    repo: "https://github.com/EdgeSecurityTeam/EHole",
    note: "Focused fingerprint rules for commonly exposed enterprise systems."
  }
];

export const builtinFingerprintRules = [
  {
    id: "wordpress",
    platform: "wordpress",
    category: "cms",
    confidence: 0.92,
    source: "wappalyzergo",
    urlPatterns: ["/wp-admin", "/wp-content", "/wp-login.php"],
    titlePatterns: ["wordpress"],
    bodyPatterns: ["wp-content", "wp-includes", "wordpress"]
  },
  {
    id: "drupal",
    platform: "drupal",
    category: "cms",
    confidence: 0.9,
    source: "wappalyzergo",
    urlPatterns: ["/sites/default", "/user/login"],
    titlePatterns: ["drupal"],
    bodyPatterns: ["drupal.settings", "/sites/default/files/", "drupal"]
  },
  {
    id: "joomla",
    platform: "joomla",
    category: "cms",
    confidence: 0.9,
    source: "wappalyzergo",
    urlPatterns: ["/administrator/", "option=com_"],
    titlePatterns: ["joomla"],
    bodyPatterns: ["joomla!", "option=com_", "content=\"joomla"]
  },
  {
    id: "thinkphp",
    platform: "thinkphp",
    category: "framework",
    confidence: 0.92,
    source: "FingerprintHub",
    titlePatterns: ["thinkphp"],
    headerPatterns: ["x-powered-by: thinkphp"],
    bodyPatterns: ["thinkphp", "thinkphp_show_page_trace"],
    minMatches: 1
  },
  {
    id: "spring-boot",
    platform: "spring-boot",
    category: "framework",
    confidence: 0.88,
    source: "wappalyzergo",
    urlPatterns: ["/actuator", "/swagger-ui", "/v3/api-docs"],
    titlePatterns: ["whitelabel error page"],
    bodyPatterns: ["whitelabel error page", "spring boot", "actuator"],
    minMatches: 1
  },
  {
    id: "apache-shiro",
    platform: "apache-shiro",
    category: "framework",
    confidence: 0.9,
    source: "FingerprintHub",
    headerPatterns: ["rememberme="],
    bodyPatterns: ["rememberme=deleteMe", "shiro"],
    minMatches: 1
  },
  {
    id: "tomcat",
    platform: "apache-tomcat",
    category: "middleware",
    confidence: 0.87,
    source: "FingerprintHub",
    titlePatterns: ["apache tomcat", "tomcat"],
    headerPatterns: ["server: apache-coyote", "server: tomcat"],
    bodyPatterns: ["/manager/html", "apache tomcat"],
    minMatches: 1
  },
  {
    id: "weblogic",
    platform: "oracle-weblogic",
    category: "middleware",
    confidence: 0.93,
    source: "EHole",
    titlePatterns: ["weblogic", "bea weblogic"],
    bodyPatterns: ["console.portal", "weblogic.server", "bea weblogic server"],
    minMatches: 1
  },
  {
    id: "nacos",
    platform: "nacos",
    category: "cloud",
    confidence: 0.93,
    source: "FingerprintHub",
    urlPatterns: ["/nacos", "/nacos/#/login"],
    titlePatterns: ["nacos"],
    bodyPatterns: ["nacos", "com.alibaba.nacos"],
    minMatches: 1
  },
  {
    id: "kibana",
    platform: "kibana",
    category: "observability",
    confidence: 0.93,
    source: "wappalyzergo",
    urlPatterns: ["/kibana", "/app/kibana", "/spaces/enter"],
    titlePatterns: ["kibana"],
    bodyPatterns: ["kibana", "elastic", "security_tenant"],
    minMatches: 1
  },
  {
    id: "jenkins",
    platform: "jenkins",
    category: "ci",
    confidence: 0.92,
    source: "wappalyzergo",
    urlPatterns: ["/jenkins/", "/login?from=%2F"],
    titlePatterns: ["jenkins"],
    headerPatterns: ["x-jenkins:"],
    bodyPatterns: ["jenkins", "x-jenkins"],
    minMatches: 1
  },
  {
    id: "cmcc-hejiaoyu",
    platform: "cmcc-hejiaoyu",
    category: "education-platform",
    confidence: 0.88,
    source: "custom-builtin",
    urlPatterns: ["/educloud/", "/ucenter/user/tologin"],
    titlePatterns: ["和教育", "云教育服务"],
    bodyPatterns: ["/educloud/static/", "您身边的教育服务专家"],
    minMatches: 1
  },
  {
    id: "cmcc-party-building",
    platform: "cmcc-party-building",
    category: "portal",
    confidence: 0.84,
    source: "custom-builtin",
    urlPatterns: ["/djy/"],
    titlePatterns: ["星火党建"],
    bodyPatterns: ["element-ui", "vue-router", "jsencrypt"],
    minMatches: 1
  },
  {
    id: "gitlab",
    platform: "gitlab",
    category: "devops",
    confidence: 0.91,
    source: "wappalyzergo",
    titlePatterns: ["gitlab"],
    bodyPatterns: ["content=\"gitlab", "gitlab"],
    headerPatterns: ["x-gitlab-meta", "gitlab-lb"],
    minMatches: 1
  },
  {
    id: "jira",
    platform: "atlassian-jira",
    category: "collaboration",
    confidence: 0.9,
    source: "wappalyzergo",
    titlePatterns: ["jira"],
    bodyPatterns: ["ajs-version-number", "atlassian jira"],
    minMatches: 1
  },
  {
    id: "confluence",
    platform: "atlassian-confluence",
    category: "collaboration",
    confidence: 0.9,
    source: "wappalyzergo",
    titlePatterns: ["confluence"],
    bodyPatterns: ["atlassian confluence", "confluence-base-url"],
    minMatches: 1
  },
  {
    id: "phpmyadmin",
    platform: "phpmyadmin",
    category: "database",
    confidence: 0.92,
    source: "wappalyzergo",
    urlPatterns: ["/phpmyadmin"],
    titlePatterns: ["phpmyadmin"],
    bodyPatterns: ["phpmyadmin", "pma_"],
    minMatches: 1
  },
  {
    id: "zabbix",
    platform: "zabbix",
    category: "monitoring",
    confidence: 0.91,
    source: "EHole",
    titlePatterns: ["zabbix"],
    bodyPatterns: ["zabbix siv", "zabbix"],
    minMatches: 1
  },
  {
    id: "sonarqube",
    platform: "sonarqube",
    category: "devops",
    confidence: 0.9,
    source: "wappalyzergo",
    titlePatterns: ["sonarqube"],
    bodyPatterns: ["sonarqube", "js-app-state"],
    minMatches: 1
  },
  {
    id: "weaver-ecology",
    platform: "weaver-ecology",
    category: "oa",
    confidence: 0.95,
    source: "FingerprintHub",
    titlePatterns: ["泛微", "ecology"],
    bodyPatterns: ["ecology", "weaver", "/wui/", "/cloudstore/"],
    urlPatterns: ["/wui/", "/cloudstore/"],
    minMatches: 1
  },
  {
    id: "weaver-eoffice",
    platform: "weaver-eoffice",
    category: "oa",
    confidence: 0.95,
    source: "FingerprintHub",
    titlePatterns: ["e-office", "泛微"],
    bodyPatterns: ["e-office", "eoffice", "weaver e-office"],
    minMatches: 1
  },
  {
    id: "tongda-oa",
    platform: "tongda-oa",
    category: "oa",
    confidence: 0.95,
    source: "EHole",
    titlePatterns: ["通达oa", "tongda"],
    bodyPatterns: ["tongda", "通达", "/ispirit/", "/static/images/tongda"],
    urlPatterns: ["/ispirit/", "/general/"],
    minMatches: 1
  },
  {
    id: "seeyon-oa",
    platform: "seeyon-oa",
    category: "oa",
    confidence: 0.94,
    source: "EHole",
    titlePatterns: ["致远", "seeyon"],
    bodyPatterns: ["seeyon", "致远", "/seeyon/"],
    urlPatterns: ["/seeyon/"],
    minMatches: 1
  },
  {
    id: "landray-oa",
    platform: "landray-oa",
    category: "oa",
    confidence: 0.94,
    source: "FingerprintHub",
    titlePatterns: ["蓝凌", "landray"],
    bodyPatterns: ["landray", "蓝凌", "ekp"],
    urlPatterns: ["/sys/ui/extend/theme/blue/"],
    minMatches: 1
  },
  {
    id: "yonyou-nc",
    platform: "yonyou-nc",
    category: "erp",
    confidence: 0.95,
    source: "EHole",
    titlePatterns: ["用友", "yonyou"],
    bodyPatterns: ["yonyou", "用友", "nc.portal", "uclient"],
    minMatches: 1
  },
  {
    id: "fanruan-finebi",
    platform: "fanruan-finebi",
    category: "bi",
    confidence: 0.94,
    source: "FingerprintHub",
    titlePatterns: ["帆软", "finebi", "finereport"],
    bodyPatterns: ["finebi", "finereport", "帆软"],
    urlPatterns: ["/webroot/decision", "/decision/login"],
    minMatches: 1
  },
  {
    id: "ruoyi",
    platform: "ruoyi",
    category: "framework",
    confidence: 0.93,
    source: "FingerprintHub",
    titlePatterns: ["若依"],
    bodyPatterns: ["ruoyi", "若依", "/ruoyi/"],
    minMatches: 1
  },
  {
    id: "hikvision",
    platform: "hikvision",
    category: "iot",
    confidence: 0.9,
    source: "EHole",
    titlePatterns: ["海康威视", "hikvision"],
    bodyPatterns: ["hikvision", "海康威视"],
    headerPatterns: ["server: hikvision"],
    minMatches: 1
  },
  {
    id: "sangfor-vpn",
    platform: "sangfor-vpn",
    category: "vpn",
    confidence: 0.93,
    source: "EHole",
    titlePatterns: ["深信服", "sangfor"],
    bodyPatterns: ["sangfor", "深信服", "edrvpn", "ssl-vpn"],
    urlPatterns: ["/por/login_psw.csp", "/svpn_login"],
    minMatches: 1
  },
  {
    id: "fortinet-fortigate",
    platform: "fortinet-fortigate",
    category: "vpn",
    confidence: 0.9,
    source: "wappalyzergo",
    titlePatterns: ["fortigate", "fortinet"],
    bodyPatterns: ["fortigate", "fortinet"],
    headerPatterns: ["server: fortiwaf"],
    minMatches: 1
  },
  {
    id: "microsoft-exchange",
    platform: "microsoft-exchange",
    category: "mail",
    confidence: 0.9,
    source: "wappalyzergo",
    urlPatterns: ["/owa/", "/ecp/", "/ews/"],
    titlePatterns: ["outlook", "exchange", "owa"],
    bodyPatterns: ["owa", "microsoft exchange", "outlook web app"],
    minMatches: 1
  }
];
