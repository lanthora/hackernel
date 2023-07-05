// SPDX-License-Identifier: GPL-2.0-only
package telegram

import (
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type Bot struct {
	Token   string
	OwnerID int64
	bot     *tgbotapi.BotAPI
}

func NewBot(token string, ownerID int64) *Bot {
	w := Bot{
		Token:   token,
		OwnerID: ownerID,
	}
	return &w
}

func (b *Bot) Connect() (err error) {
	bot, err := tgbotapi.NewBotAPI(b.Token)
	if err != nil {
		return
	}
	b.bot = bot
	return
}

func (b *Bot) SendTextToOwner(text string) (err error) {
	msg := tgbotapi.NewMessage(b.OwnerID, text)
	msg.DisableWebPagePreview = true
	_, err = b.bot.Send(msg)
	return
}

func (b *Bot) SendHtmlToOwner(text string) (err error) {
	msg := tgbotapi.NewMessage(b.OwnerID, text)
	msg.DisableWebPagePreview = true
	msg.ParseMode = tgbotapi.ModeHTML
	_, err = b.bot.Send(msg)
	return
}
