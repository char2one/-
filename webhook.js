import { buffer } from 'micro';
import crypto from 'crypto';

export const config = {
  api: {
    bodyParser: false,
  },
};

const PACHCA_TOKEN = process.env.PACHCA_TOKEN;
const PACHCA_WEBHOOK_SECRET = process.env.PACHCA_WEBHOOK_SECRET;
const WELCOME_MESSAGE_TYPE = process.env.WELCOME_MESSAGE_TYPE || 'extended';

const messages = {
  extended: `
👋 Добро пожаловать в команду Академии Международного Бизнеса{{name_greeting}}!

Мы очень рады, что ты с нами! 
Желаем быстрой адаптации, интересных задач и крутых результатов в нашей дружной команде. Не стесняйся задавать вопросы – здесь всегда помогут и поддержат.

Важно для всех:
📌 В ветке отдела есть форма ежедневного отчёта, которую необходимо заполнять каждый день до 21:00. 
Это помогает нам быть на одной волне и эффективно работать.

Давай настраиваться на продуктивную работу и отличное взаимодействие! 🚀

В общем чате АМБ тебя скоро поприветствуют и там ты увидишь всех нас. 

В ветке "отчет отдела" — вся команда твоего отдела, знакомься!

P.S. Если что-то непонятно – обращайся, с радостью поможем! 😊
`,
};

function verifySignature(req, secret) {
  const signature = req.headers['x-pachca-signature'];
  if (!signature) return false;

  const buf = Buffer.from(req.rawBody, 'utf8');
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(buf);
  const digest = hmac.digest('hex');

  return signature === digest;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).send('Method Not Allowed');
    return;
  }

  // Получаем необработанное тело запроса
  req.rawBody = (await buffer(req)).toString('utf8');

  // Проверяем подпись
  if (!verifySignature(req, PACHCA_WEBHOOK_SECRET)) {
    res.status(401).send('Unauthorized');
    return;
  }

  const event = JSON.parse(req.rawBody);

  // Проверяем событие добавления нового участника
  if (
    event.type === 'space_members_changed' &&
    event.data.added &&
    event.data.added.length > 0
  ) {
    for (const user of event.data.added) {
      // Отправка сообщения пользователю (через API Пачки)
      await fetch('https://api.pachca.com/v1/messages/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${PACHCA_TOKEN}`,
        },
        body: JSON.stringify({
          recipient_id: user.id,
          text: messages[WELCOME_MESSAGE_TYPE].replace(
            '{{name_greeting}}',
            user.name ? `, ${user.name}` : ''
          ),
        }),
      });
    }
  }

  res.status(200).send('OK');
}
