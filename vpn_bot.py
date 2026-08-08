import asyncio
import html
from datetime import datetime
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, BufferedInputFile

import config
import wg_manager

bot = Bot(token=config.VPN_BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())

class WGStates(StatesGroup):
    waiting_for_device_name = State()

def is_admin(user_id: int) -> bool:
    if not config.ADMIN_CHAT_ID or config.ADMIN_CHAT_ID == 0:
        return True
    return user_id == config.ADMIN_CHAT_ID

def build_main_keyboard() -> InlineKeyboardMarkup:
    devices = wg_manager.list_devices()
    kb = []
    
    for dev in devices:
        name = dev.get("name", "Device")
        ip = dev.get("ip", "")
        dev_id = dev.get("id", "")
        kb.append([
            InlineKeyboardButton(text=f"📱 {name} ({ip})", callback_data=f"info_wg_{dev_id}"),
            InlineKeyboardButton(text=f"❌ Revoke", callback_data=f"del_wg_{dev_id}")
        ])
        
    kb.append([InlineKeyboardButton(text="➕ Add iPhone / Device (QR Code)", callback_data="add_wg_btn")])
    kb.append([InlineKeyboardButton(text="🔄 Refresh Status", callback_data="refresh_status")])
    return InlineKeyboardMarkup(inline_keyboard=kb)

def get_status_text() -> str:
    devices = wg_manager.list_devices()
    
    return (
        f"🔐 **NET-SENTINEL // WIREGUARD VPN BOT**\n\n"
        f"Base Layer VPN Tunnel Manager for iPhone 12 / Devices.\n\n"
        f"▪️ VPS Gateway: `{config.VPS_IP}`\n"
        f"▪️ Subnet: `10.8.0.0/24`\n"
        f"▪️ Listen Port: `{config.WG_PORT}`\n"
        f"▪️ Active Tunnels: `{len(devices)}`\n\n"
        f" Server Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
    )

@dp.message(Command("start", "menu"))
async def cmd_start(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        await message.reply(
            f"⛔ <b>Access Denied</b>\n\n"
            f"Your Telegram User ID is: <code>{message.from_user.id}</code>\n"
            f"Configured ADMIN_CHAT_ID: <code>{config.ADMIN_CHAT_ID}</code>\n\n"
            f"<i>Add your ID to .env file if this is your account.</i>",
            parse_mode="HTML"
        )
        return
    await state.clear()
    await message.answer(get_status_text(), reply_markup=build_main_keyboard(), parse_mode="Markdown")

@dp.callback_query(F.data == "refresh_status")
async def cb_refresh(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Access Denied", show_alert=True)
        return
    await state.clear()
    await callback.answer("Refreshed!")
    await callback.message.edit_text(get_status_text(), reply_markup=build_main_keyboard(), parse_mode="Markdown")

@dp.callback_query(F.data == "add_wg_btn")
async def cb_add_wg_prompt(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Access Denied", show_alert=True)
        return
    await state.set_state(WGStates.waiting_for_device_name)
    cancel_kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Cancel", callback_data="refresh_status")]
    ])
    await callback.message.edit_text(
        "📱 **Enter Device Name / Label:**\n\n"
        "Examples:\n"
        "▪️ `iPhone_12_Alpha`\n"
        "▪️ `iPhone_Work_01`\n"
        "▪️ `MacBook_Pro`",
        reply_markup=cancel_kb,
        parse_mode="Markdown"
    )

@dp.message(WGStates.waiting_for_device_name)
async def process_add_wg_device(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    dev_name = message.text.strip().replace(" ", "_")
    if not dev_name:
        return
    
    await state.clear()
    
    vps_ip = config.VPS_IP or "127.0.0.1"
    try:
        device_data, qr_bytes, conf_str = wg_manager.create_device(dev_name, vps_ip)
        safe_name = html.escape(device_data["name"])
        safe_ip = html.escape(device_data["ip"])
        
        photo = BufferedInputFile(qr_bytes, filename=f"{dev_name}_wireguard.png")
        
        caption = (
            f"✅ <b>WireGuard VPN Config Created!</b>\n\n"
            f"📱 Device: <b>{safe_name}</b>\n"
            f"🌐 Internal IP: <code>{safe_ip}/32</code>\n"
            f"🔑 Status: <b>Ready for Handshake</b>\n\n"
            f"📲 <b>How to connect on iPhone 12:</b>\n"
            f"1. Open the <b>WireGuard</b> app on iOS.\n"
            f"2. Tap <b>+</b> → <b>Scan from QR Code</b>.\n"
            f"3. Scan the image below! Instant setup."
        )
        
        await message.answer_photo(photo=photo, caption=caption, parse_mode="HTML")
        await message.answer(get_status_text(), reply_markup=build_main_keyboard(), parse_mode="Markdown")
    except Exception as e:
        await message.reply(f"⚠️ Failed generating WireGuard config: {html.escape(str(e))}", parse_mode="HTML")

@dp.callback_query(F.data.startswith("del_wg_"))
async def cb_del_wg(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Access Denied", show_alert=True)
        return
    dev_id = callback.data.replace("del_wg_", "")
    removed = wg_manager.delete_device(dev_id)
    if removed:
        await callback.answer(f"✅ Device revoked!")
    else:
        await callback.answer("⚠️ Device not found")
    await callback.message.edit_text(get_status_text(), reply_markup=build_main_keyboard(), parse_mode="Markdown")

async def main():
    print("[+] Starting NetSentinel WireGuard VPN Bot...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
