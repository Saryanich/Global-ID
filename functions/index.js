"use strict";

const admin = require("firebase-admin");
const crypto = require("node:crypto");
const { defineSecret } = require("firebase-functions/params");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { onDocumentCreated, onDocumentUpdated } = require("firebase-functions/v2/firestore");
const logger = require("firebase-functions/logger");

admin.initializeApp();

const db = admin.firestore();
const auth = admin.auth();

const ITGLOBAL_MAIL_WEBAPP_URL = defineSecret("ITGLOBAL_MAIL_WEBAPP_URL");
const ITGLOBAL_MAIL_WEBAPP_TOKEN = defineSecret("ITGLOBAL_MAIL_WEBAPP_TOKEN");
const MAIL_SECRETS = [
  ITGLOBAL_MAIL_WEBAPP_URL,
  ITGLOBAL_MAIL_WEBAPP_TOKEN
];
const GLOBAL_ID_URL = "https://saryanich.github.io/Global-ID/";
const EMPLOYEE_PORTAL_URL = "https://saryanich.github.io/for_developers/employee.html";
const MAX_RATE_PER_HOUR = 5;
const MIN_INTERVAL_MS = 60 * 1000;
const EVENT_LOCK_MS = 10 * 60 * 1000;

function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildEmailHtml(options) {
  const title = options.title || "Уведомление IT Global";
  const preheader = options.preheader || title;
  const content = options.content || "";
  const button = options.buttonText && options.buttonUrl
    ? '<div style="text-align:center;margin:30px 0 24px">' +
      '<a href="' + escapeHtml(options.buttonUrl) + '" style="display:inline-block;padding:15px 26px;border-radius:12px;background:linear-gradient(100deg,#07965c,#1684db);color:#ffffff;text-decoration:none;font-weight:700;font-size:15px">' +
      escapeHtml(options.buttonText) + '</a></div>'
    : "";

  return '<!doctype html><html lang="ru"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1"><title>' + escapeHtml(title) + '</title></head>' +
    '<body style="margin:0;padding:28px 12px;background:#eef3f8;font-family:Arial,Helvetica,sans-serif;color:#172437">' +
    '<div style="display:none;max-height:0;overflow:hidden;opacity:0">' + escapeHtml(preheader) + '</div>' +
    '<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:620px;margin:0 auto;background:#ffffff;border-radius:22px;overflow:hidden;box-shadow:0 12px 38px rgba(20,45,75,.10)">' +
    '<tr><td style="padding:28px 30px;background:linear-gradient(110deg,#061f2c,#0b3850 58%,#27214b)">' +
    '<div style="font-size:12px;letter-spacing:3px;font-weight:800;color:#8ee7c1">IT GLOBAL</div>' +
    '<div style="margin-top:8px;font-size:25px;line-height:1.25;font-weight:800;color:#ffffff">Global ID</div>' +
    '<div style="margin-top:7px;font-size:13px;color:#c3d9e8">Люди • технологии • возможности</div>' +
    '</td></tr><tr><td style="padding:34px 30px 28px">' +
    '<h1 style="margin:0 0 18px;font-size:23px;line-height:1.3;color:#12243a">' + escapeHtml(title) + '</h1>' +
    '<div style="font-size:15px;line-height:1.75;color:#42536a">' + content + '</div>' + button +
    '<div style="height:1px;background:#e7edf3;margin:28px 0 20px"></div>' +
    '<div style="font-size:14px;line-height:1.7;color:#43536a">С уважением,<br><strong style="color:#152b40">Команда IT Global</strong></div>' +
    '<div style="margin-top:14px;font-size:12px;color:#8795a6">Это автоматическое уведомление. Пожалуйста, не отвечайте на него.</div>' +
    '</td></tr></table></body></html>';
}

async function sendMail(message) {
  const endpoint = ITGLOBAL_MAIL_WEBAPP_URL.value();
  const token = ITGLOBAL_MAIL_WEBAPP_TOKEN.value();

  if (!endpoint || !token) {
    throw new Error("IT Global Mail gateway is not configured");
  }
  if (!endpoint.startsWith("https://script.google.com/macros/s/")) {
    throw new Error("Invalid IT Global Mail gateway URL");
  }

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      token: token,
      to: normalizeEmail(message.to),
      subject: String(message.subject || ""),
      text: String(message.text || ""),
      html: String(message.html || "")
    }),
    signal: AbortSignal.timeout(20000)
  });

  const result = await response.json().catch(() => null);
  if (!response.ok || !result?.ok) {
    const errorCode = result?.error || ("http_" + response.status);
    throw new Error("IT Global Mail gateway rejected the message: " + errorCode);
  }
}

async function reserveRateLimit(email, purpose, ipAddress) {
  const emailKey = crypto.createHash("sha256")
    .update(purpose + ":email:" + normalizeEmail(email))
    .digest("hex");
  const checks = [{
    ref: db.collection("mail_rate_limits").doc(emailKey),
    max: MAX_RATE_PER_HOUR,
    minInterval: MIN_INTERVAL_MS
  }];

  // Keep only a hash of the caller IP; never store the raw address.
  const ip = typeof ipAddress === "string" ? ipAddress.trim().split(",")[0] : "";
  if (ip) {
    const ipKey = crypto.createHash("sha256")
      .update(purpose + ":ip:" + ip)
      .digest("hex");
    checks.push({
      ref: db.collection("mail_rate_limits").doc(ipKey),
      max: 20,
      minInterval: 3000
    });
  }

  const now = Date.now();
  return db.runTransaction(async (transaction) => {
    const snapshots = await Promise.all(checks.map((item) => transaction.get(item.ref)));
    const updated = [];

    for (let index = 0; index < checks.length; index++) {
      const data = snapshots[index].exists ? snapshots[index].data() : {};
      const attempts = Array.isArray(data.attempts)
        ? data.attempts.filter((time) => Number.isFinite(time) && now - time < 60 * 60 * 1000)
        : [];
      const lastAttempt = attempts.length ? attempts[attempts.length - 1] : 0;

      if (attempts.length >= checks[index].max ||
          (lastAttempt && now - lastAttempt < checks[index].minInterval)) {
        return false;
      }
      attempts.push(now);
      updated.push({ ref: checks[index].ref, attempts: attempts });
    }

    for (const item of updated) {
      transaction.set(item.ref, {
        purpose: purpose,
        attempts: item.attempts,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    }
    return true;
  });
}

async function sendOnce(eventKey, message) {
  const id = crypto.createHash("sha256").update(eventKey).digest("hex");
  const ref = db.collection("mail_delivery_events").doc(id);
  const now = Date.now();

  const claimed = await db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(ref);
    const data = snapshot.exists ? snapshot.data() : {};
    if (data.status === "sent") return false;

    const startedAt = Number(data.startedAtMs || 0);
    if (data.status === "sending" && now - startedAt < EVENT_LOCK_MS) return false;

    transaction.set(ref, {
      status: "sending",
      startedAtMs: now,
      attempts: Number(data.attempts || 0) + 1,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    return true;
  });

  if (!claimed) return false;

  try {
    await sendMail(message);
    await ref.set({
      status: "sent",
      sentAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      lastError: admin.firestore.FieldValue.delete()
    }, { merge: true });
    return true;
  } catch (error) {
    await ref.set({
      status: "failed",
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      lastError: String(error?.message || error).slice(0, 300)
    }, { merge: true });
    throw error;
  }
}

exports.sendCustomVerificationEmail = onCall({
  secrets: MAIL_SECRETS,
  maxInstances: 3
}, async (request) => {
  if (!request.auth?.uid) {
    throw new HttpsError("unauthenticated", "Для отправки письма войдите в Global ID.");
  }

  const user = await auth.getUser(request.auth.uid);
  const email = normalizeEmail(user.email);
  if (!isValidEmail(email)) {
    throw new HttpsError("failed-precondition", "У аккаунта не указан корректный email.");
  }
  if (user.emailVerified) return { ok: true, alreadyVerified: true };

  const allowed = await reserveRateLimit(email, "email_verification", request.rawRequest?.ip);
  if (!allowed) {
    throw new HttpsError("resource-exhausted", "Слишком много запросов. Повторите попытку позже.");
  }

  try {
    const link = await auth.generateEmailVerificationLink(email);
    const html = buildEmailHtml({
      title: "Подтвердите электронную почту",
      preheader: "Подтверждение адреса Global ID",
      content: '<p>Здравствуйте!</p><p>Вы регистрируете аккаунт <strong>Global ID</strong>. Подтвердите, что этот адрес электронной почты принадлежит вам.</p><p>Если вы не создавали аккаунт IT Global, просто проигнорируйте это письмо.</p>',
      buttonText: "Подтвердить email",
      buttonUrl: link
    });
    await sendMail({
      to: email,
      subject: "Подтверждение электронной почты — Global ID",
      html: html,
      text: "Здравствуйте!\n\nПодтвердите адрес электронной почты для Global ID:\n" + link + "\n\nЕсли вы не создавали аккаунт, проигнорируйте это письмо.\n\nКоманда IT Global"
    });
    return { ok: true };
  } catch (error) {
    logger.error("Custom verification email failed", { code: error?.code || "unknown" });
    throw new HttpsError("unavailable", "Фирменная отправка писем временно недоступна.");
  }
});

exports.requestCustomPasswordReset = onCall({
  secrets: MAIL_SECRETS,
  maxInstances: 3
}, async (request) => {
  let email = "";

  if (request.auth?.uid) {
    const user = await auth.getUser(request.auth.uid);
    email = normalizeEmail(user.email);
    const requestedEmail = normalizeEmail(request.data?.email);
    if (requestedEmail && email && requestedEmail !== email) return { ok: true };
  } else {
    email = normalizeEmail(request.data?.email);
  }

  if (!isValidEmail(email)) return { ok: true };

  const allowed = await reserveRateLimit(email, "password_reset", request.rawRequest?.ip);
  if (!allowed) {
    throw new HttpsError("resource-exhausted", "Слишком много запросов. Повторите попытку позже.");
  }

  try {
    const link = await auth.generatePasswordResetLink(email);
    const html = buildEmailHtml({
      title: "Восстановление пароля",
      preheader: "Ссылка для создания нового пароля Global ID",
      content: '<p>Здравствуйте!</p><p>Вы запросили восстановление пароля для аккаунта <strong>Global ID</strong>.</p><p>Нажмите кнопку ниже, чтобы создать новый пароль. Сброс пароля не снимает блокировку аккаунта и не отключает проверку доверенного устройства.</p><p>Если вы не запрашивали восстановление, просто проигнорируйте это письмо.</p>',
      buttonText: "Создать новый пароль",
      buttonUrl: link
    });
    await sendMail({
      to: email,
      subject: "Восстановление пароля — Global ID",
      html: html,
      text: "Здравствуйте!\n\nВы запросили восстановление пароля Global ID. Создайте новый пароль по ссылке:\n" + link + "\n\nСброс пароля не снимает блокировку аккаунта и не отключает проверку доверенного устройства.\n\nЕсли вы не запрашивали восстановление, проигнорируйте это письмо.\n\nКоманда IT Global"
    });
  } catch (error) {
    if (error?.code === "auth/user-not-found") return { ok: true };
    logger.error("Custom password reset email failed", { code: error?.code || "unknown" });
    throw new HttpsError("unavailable", "Фирменная отправка писем временно недоступна.");
  }

  return { ok: true };
});

exports.notifyPromoAccepted = onDocumentUpdated({
  document: "join_requests/{requestId}",
  retry: true,
  secrets: MAIL_SECRETS,
  maxInstances: 2
}, async (event) => {
  const before = event.data?.before?.data();
  const after = event.data?.after?.data();
  if (!before || !after || before.status === "accepted" || after.status !== "accepted") return;
  if (!after.uid) {
    logger.warn("Accepted Promo request has no UID", { requestId: event.params.requestId });
    return;
  }

  let email = normalizeEmail(after.accountEmail);
  try {
    const user = await auth.getUser(after.uid);
    email = normalizeEmail(user.email || email);
  } catch (_) {}

  if (!isValidEmail(email)) {
    logger.warn("Accepted Promo request has no valid recipient", { requestId: event.params.requestId });
    return;
  }

  const name = escapeHtml(after.fullname || "участник IT Global");
  const globalId = escapeHtml(after.globalId || "");
  const html = buildEmailHtml({
    title: "Ваша заявка принята!",
    preheader: "Добро пожаловать в команду IT Global",
    content: '<p>Здравствуйте, ' + name + '!</p><p>Отличные новости: ваша заявка на вступление в команду <strong>IT Global</strong> одобрена.</p><p>Ваша учётная запись Global ID получила доступ сотрудника' +
      (globalId ? ' (Global ID: <strong>' + globalId + '</strong>)' : '') +
      '.</p><p>Теперь можно перейти в кабинет сотрудника и ознакомиться с доступными заданиями.</p>',
    buttonText: "Открыть кабинет сотрудника",
    buttonUrl: EMPLOYEE_PORTAL_URL
  });

  await sendOnce("promo-accepted:" + event.params.requestId + ":" + after.uid, {
    to: email,
    subject: "Ваша заявка принята — IT Global",
    html: html,
    text: "Здравствуйте, " + (after.fullname || "участник IT Global") + "!\n\nВаша заявка на вступление в IT Global одобрена. Ваша учётная запись Global ID получила доступ сотрудника.\n\nОткрыть кабинет сотрудника: " + EMPLOYEE_PORTAL_URL + "\n\nКоманда IT Global"
  });
});

exports.notifyEmployeesOnTaskCreated = onDocumentCreated({
  document: "tasks/{taskId}",
  retry: true,
  secrets: MAIL_SECRETS,
  maxInstances: 2
}, async (event) => {
  const task = event.data?.data();
  if (!task || task.status !== "active") return;

  const usersSnapshot = await db.collection("users").where("role", "==", "employee").get();
  const eligibleLevels = Array.isArray(task.eligibleLevels)
    ? task.eligibleLevels.map(Number)
    : null;
  const recipients = [];

  for (const userDoc of usersSnapshot.docs) {
    const employee = userDoc.data() || {};
    if (employee.accountLocked === true || employee.globalIdAccess === false) continue;
    if (task.assigneeId && task.assigneeId !== userDoc.id) continue;

    const level = Number(employee.programmerLevel || 0);
    if (eligibleLevels && (!level || !eligibleLevels.includes(level))) continue;

    let email = normalizeEmail(employee.email);
    try {
      const authUser = await auth.getUser(userDoc.id);
      email = normalizeEmail(authUser.email || email);
    } catch (_) {}
    if (isValidEmail(email)) recipients.push({ uid: userDoc.id, email: email });
  }

  const uniqueRecipients = [...new Map(recipients.map((item) => [item.uid, item])).values()];
  if (!uniqueRecipients.length) {
    logger.info("New task has no eligible email recipients", { taskId: event.params.taskId });
    return;
  }

  const title = escapeHtml(String(task.title || "Новое задание").slice(0, 180));
  const description = escapeHtml(String(task.description || "Откройте кабинет сотрудника, чтобы посмотреть подробности.").slice(0, 1800));
  const reward = Number.isFinite(Number(task.reward)) ? Number(task.reward) : 0;

  const results = await Promise.allSettled(uniqueRecipients.map((recipient) => {
    const html = buildEmailHtml({
      title: "Новое задание для сотрудника",
      preheader: "Опубликовано задание: " + String(task.title || "Новое задание").slice(0, 100),
      content: '<p>Здравствуйте!</p><p>В IT Global опубликовано новое задание, доступное для вашего уровня.</p>' +
        '<div style="padding:18px;background:#f2f7fb;border:1px solid #e0eaf2;border-radius:14px;margin:18px 0">' +
        '<div style="font-size:18px;font-weight:800;color:#17334b">' + title + '</div>' +
        '<div style="margin-top:10px;white-space:pre-wrap">' + description + '</div>' +
        '<div style="margin-top:14px;font-weight:700;color:#087e59">Награда: ' + reward + ' баллов</div></div>' +
        '<p>Откройте кабинет, чтобы принять задание или посмотреть остальные задачи.</p>',
      buttonText: "Посмотреть задания",
      buttonUrl: EMPLOYEE_PORTAL_URL
    });
    return sendOnce("task-created:" + event.params.taskId + ":" + recipient.uid, {
      to: recipient.email,
      subject: "Новое задание IT Global: " + String(task.title || "Без названия").slice(0, 120),
      html: html,
      text: "Здравствуйте!\n\nВ IT Global опубликовано новое задание: " + String(task.title || "Новое задание") +
        "\n\n" + String(task.description || "") + "\n\nНаграда: " + reward +
        " баллов.\n\nПосмотреть задания: " + EMPLOYEE_PORTAL_URL + "\n\nКоманда IT Global"
    });
  }));

  const failed = results.filter((result) => result.status === "rejected");
  if (failed.length) {
    logger.error("Some task notification emails failed", {
      taskId: event.params.taskId,
      failedCount: failed.length,
      recipientCount: uniqueRecipients.length
    });
    throw new Error("Failed to send " + failed.length + " task notification(s)");
  }

  logger.info("Task notification emails processed", {
    taskId: event.params.taskId,
    recipientCount: uniqueRecipients.length
  });
});
