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
    """Verifies whether the message sender is an authorized administrator"""
    if not config.ADMIN_CHAT_ID or config.ADMIN_CHAT_ID == 0:
        return True
    return user_id == config.ADMIN_CHAT_ID


def build_main_keyboard() -> InlineKeyboardMarkup:
    """Constructs main menu keyboard with real-time peer indicators"""
    devices = wg_manager.list_devices()
    peer_stats = wg_manager.get_peer_stats()
    kb = []
    
    for dev in devices:
        name = dev.get("name", "Device")
        ip = dev.get("ip", "")
        dev_id = dev.get("id", "")
        pub_key = dev.get("public_key", "")
        
        stat = peer_stats.get(pub_key, {})
        is_online = stat.get("is_online", False)
        status_dot = "🟢" if is_online else "⚪"
        
        kb.append([
            InlineKeyboardButton(text=f"{status_dot} {name} ({ip})", callback_data=f"info_wg_{dev_id}"),
            InlineKeyboardButton(text="❌ Revoke", callback_data=f"del_wg_{dev_id}")
        ])
        
    kb.append([InlineKeyboardButton(text="➕ Add Device (iOS / Android / PC)", callback_data="add_wg_btn")])
    kb.append([InlineKeyboardButton(text="🔄 Refresh Status", callback_data="refresh_status")])
    return InlineKeyboardMarkup(inline_keyboard=kb)


def get_status_text() -> str:
    """Builds dashboard status overview text with live tunnel statistics"""
    devices = wg_manager.list_devices()
    peer_stats = wg_manager.get_peer_stats()
    
    online_count = 0
    for dev in devices:
        pub = dev.get("public_key", "")
        if peer_stats.get(pub, {}).get("is_online", False):
            online_count += 1
            
    admin_warning = ""
    if not config.ADMIN_CHAT_ID or config.ADMIN_CHAT_ID == 0:
        admin_warning = (
            "\n⚠️ <b>SECURITY NOTICE:</b> <code>ADMIN_CHAT_ID</code> is not configured in <code>.env</code>. "
            "Anyone can access this bot until configured!\n"
        )
    
    vps_ip_display = html.escape(config.VPS_IP or "127.0.0.1")
    subnet_display = html.escape(getattr(config, "WG_SUBNET", "10.8.0") + ".0/24")
    port_display = config.WG_PORT
    server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return (
        f"🔐 <b>NET-SENTINEL // WIREGUARD VPN GATEWAY</b>\n"
        f"{admin_warning}\n"
        f"<b>Gateway Information:</b>\n"
        f"▪️ <b>VPS Endpoint:</b> <code>{vps_ip_display}</code>\n"
        f"▪️ <b>Subnet:</b> <code>{subnet_display}</code>\n"
        f"▪️ <b>Listen Port:</b> <code>{port_display} UDP</code>\n"
        f"▪️ <b>Registered Peers:</b> <code>{len(devices)}</code>\n"
        f"▪️ <b>Currently Online:</b> <code>{online_count}</code> 🟢\n\n"
        f"🕒 <i>Server Time: {server_time}</i>"
    )


@dp.message(Command("start", "menu"))
async def cmd_start(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        await message.reply(
            f"⛔ <b>Access Denied</b>\n\n"
            f"Your Telegram User ID is: <code>{message.from_user.id}</code>\n"
            f"Configured ADMIN_CHAT_ID: <code>{config.ADMIN_CHAT_ID}</code>\n\n"
            f"<i>Add your ID to the .env file on your VPS to claim admin access.</i>",
            parse_mode="HTML"
        )
        return
    await state.clear()
    await message.answer(get_status_text(), reply_markup=build_main_keyboard(), parse_mode="HTML")


@dp.callback_query(F.data == "refresh_status")
async def cb_refresh(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Access Denied", show_alert=True)
        return
    await state.clear()
    await callback.answer("Status updated!")
    await callback.message.edit_text(get_status_text(), reply_markup=build_main_keyboard(), parse_mode="HTML")


@dp.callback_query(F.data.startswith("info_wg_"))
async def cb_device_info(callback: types.CallbackQuery):
    """Displays detailed card for a specific device with stats and action buttons"""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Access Denied", show_alert=True)
        return
    
    dev_id = callback.data.replace("info_wg_", "")
    device = wg_manager.get_device_by_id(dev_id)
    if not device:
        await callback.answer("⚠️ Device not found!", show_alert=True)
        await callback.message.edit_text(get_status_text(), reply_markup=build_main_keyboard(), parse_mode="HTML")
        return
    
    pub_key = device.get("public_key", "")
    peer_stats = wg_manager.get_peer_stats()
    stat = peer_stats.get(pub_key, {})
    
    is_online = stat.get("is_online", False)
    status_badge = "🟢 Online" if is_online else "⚪ Offline"
    last_hs = stat.get("last_handshake_str", "Never")
    rx_str = stat.get("rx_str", "0 B")
    tx_str = stat.get("tx_str", "0 B")
    endpoint = stat.get("endpoint") or "None"
    
    name = html.escape(device.get("name", "Device"))
    ip = html.escape(device.get("ip", "N/A"))
    created_at = html.escape(str(device.get("created_at", "N/A")))
    pub_short = html.escape(pub_key[:16] + "..." if pub_key else "N/A")
    
    text = (
        f"📱 <b>Device Details: {name}</b>\n\n"
        f"▪️ <b>Status:</b> {status_badge}\n"
        f"▪️ <b>Assigned IP:</b> <code>{ip}/32</code>\n"
        f"▪️ <b>Last Handshake:</b> <code>{html.escape(last_hs)}</code>\n"
        f"▪️ <b>Traffic (DL / UL):</b> 📥 <code>{rx_str}</code> | 📤 <code>{tx_str}</code>\n"
        f"▪️ <b>Client Endpoint:</b> <code>{html.escape(endpoint)}</code>\n"
        f"▪️ <b>Public Key:</b> <code>{pub_short}</code>\n"
        f"▪️ <b>Created At:</b> <code>{created_at}</code>\n"
    )
    
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📷 Show QR Code", callback_data=f"qr_wg_{dev_id}"),
            InlineKeyboardButton(text="📄 Download .conf", callback_data=f"file_wg_{dev_id}")
        ],
        [
            InlineKeyboardButton(text="❌ Revoke Device", callback_data=f"del_wg_{dev_id}"),
            InlineKeyboardButton(text="🔙 Back to Dashboard", callback_data="refresh_status")
        ]
    ])
    
    await callback.answer()
    await callback.message.edit_text(text, reply_markup=kb, parse_mode="HTML")


@dp.callback_query(F.data.startswith("qr_wg_"))
async def cb_send_qr(callback: types.CallbackQuery):
    """Sends QR code image for the requested device"""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Access Denied", show_alert=True)
        return
    
    dev_id = callback.data.replace("qr_wg_", "")
    bundle = wg_manager.get_device_bundle(dev_id)
    if not bundle:
        await callback.answer("⚠️ Device not found!", show_alert=True)
        return
    
    device_data, qr_bytes, _ = bundle
    dev_name = device_data.get("name", "device")
    safe_name = html.escape(dev_name)
    safe_ip = html.escape(device_data.get("ip", ""))
    
    photo = BufferedInputFile(qr_bytes, filename=f"{dev_name}_wg_qr.png")
    caption = (
        f"📱 <b>WireGuard QR Code: {safe_name}</b>\n"
        f"🌐 IP: <code>{safe_ip}/32</code>\n\n"
        f"<i>Scan this in WireGuard app on iOS or Android.</i>"
    )
    await callback.answer()
    await callback.message.answer_photo(photo=photo, caption=caption, parse_mode="HTML")


@dp.callback_query(F.data.startswith("file_wg_"))
async def cb_send_conf_file(callback: types.CallbackQuery):
    """Sends .conf file document for importing into WireGuard on PC, Mac or routers"""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Access Denied", show_alert=True)
        return
    
    dev_id = callback.data.replace("file_wg_", "")
    bundle = wg_manager.get_device_bundle(dev_id)
    if not bundle:
        await callback.answer("⚠️ Device not found!", show_alert=True)
        return
    
    device_data, _, conf_str = bundle
    dev_name = device_data.get("name", "wireguard")
    safe_name = html.escape(dev_name)
    
    conf_doc = BufferedInputFile(conf_str.encode("utf-8"), filename=f"{dev_name}.conf")
    caption = (
        f"📄 <b>Configuration File: {safe_name}.conf</b>\n\n"
        f"<i>Import this into WireGuard on Windows, macOS, Linux, or router.</i>"
    )
    await callback.answer()
    await callback.message.answer_document(document=conf_doc, caption=caption, parse_mode="HTML")


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
        "📱 <b>Enter Device Label / Name:</b>\n\n"
        "Examples:\n"
        "▪️ <code>iPhone_12_Personal</code>\n"
        "▪️ <code>Work_MacBook</code>\n"
        "▪️ <code>Home_PC</code>\n\n"
        "<i>Spaces and special characters will be safely formatted.</i>",
        reply_markup=cancel_kb,
        parse_mode="HTML"
    )


@dp.message(WGStates.waiting_for_device_name)
async def process_add_wg_device(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    raw_name = message.text.strip()
    if not raw_name:
        return
    
    await state.clear()
    vps_ip = config.VPS_IP or "127.0.0.1"
    
    try:
        device_data, qr_bytes, conf_str = wg_manager.create_device(raw_name, vps_ip)
        dev_name = device_data["name"]
        safe_name = html.escape(dev_name)
        safe_ip = html.escape(device_data["ip"])
        
        # 1. Send QR Code Photo
        photo = BufferedInputFile(qr_bytes, filename=f"{dev_name}_wireguard.png")
        caption = (
            f"✅ <b>WireGuard VPN Config Created!</b>\n\n"
            f"📱 Device: <b>{safe_name}</b>\n"
            f"🌐 Assigned IP: <code>{safe_ip}/32</code>\n"
            f"🔑 Status: <b>Ready for Handshake</b>\n\n"
            f"📲 <b>Mobile Setup (iOS / Android):</b>\n"
            f"1. Open <b>WireGuard</b> app.\n"
            f"2. Tap <b>+</b> → <b>Create from QR code</b>.\n"
            f"3. Scan the image below."
        )
        await message.answer_photo(photo=photo, caption=caption, parse_mode="HTML")
        
        # 2. Also send .conf file document for PC / Laptop
        conf_doc = BufferedInputFile(conf_str.encode("utf-8"), filename=f"{dev_name}.conf")
        await message.answer_document(
            document=conf_doc,
            caption=f"💻 <b>Desktop Config:</b> <code>{safe_name}.conf</code> (Import directly in WireGuard for Windows/Mac/Linux)",
            parse_mode="HTML"
        )
        
        # 3. Return to Dashboard
        await message.answer(get_status_text(), reply_markup=build_main_keyboard(), parse_mode="HTML")
    except Exception as e:
        await message.reply(f"⚠️ <b>Failed generating WireGuard config:</b> <code>{html.escape(str(e))}</code>", parse_mode="HTML")


@dp.callback_query(F.data.startswith("del_wg_"))
async def cb_del_wg(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Access Denied", show_alert=True)
        return
    dev_id = callback.data.replace("del_wg_", "")
    removed = wg_manager.delete_device(dev_id)
    if removed:
        await callback.answer("✅ Device revoked!")
    else:
        await callback.answer("⚠️ Device not found!")
    await callback.message.edit_text(get_status_text(), reply_markup=build_main_keyboard(), parse_mode="HTML")


async def main():
    print("[+] Starting NetSentinel WireGuard VPN Bot...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
