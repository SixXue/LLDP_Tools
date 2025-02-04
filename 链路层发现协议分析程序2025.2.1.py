import sys
import os
import subprocess
import ctypes
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QComboBox, QPushButton,
    QTreeWidget, QTreeWidgetItem, QMessageBox, QTextEdit, QMenu
)
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import QThread, Signal, Qt
import tempfile
import shutil
import re
import datetime
from datetime import datetime
import atexit
import ctypes
from ctypes import wintypes

# 确保 tcpdump.exe 解压到临时目录
temp_dir = tempfile.gettempdir()
tcpdump_temp_path = os.path.join(temp_dir, "tcpdump.exe")

# 将 tcpdump.exe 解压到临时目录
def deploy_tcpdump():
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    tcpdump_source_path = os.path.join(base_path, "tcpdump.exe")
    if os.path.exists(tcpdump_source_path):
        shutil.copy(tcpdump_source_path, tcpdump_temp_path)
        print(f"tcpdump.exe 已解压到: {tcpdump_temp_path}")
    else:
        raise FileNotFoundError(f"tcpdump.exe 未找到，路径: {tcpdump_source_path}")

# 在程序退出时删除临时目录中的 tcpdump.exe
def cleanup_tcpdump():
    if os.path.exists(tcpdump_temp_path):
        try:
            os.remove(tcpdump_temp_path)
        except PermissionError as e:
            print(f"无法删除 tcpdump.exe: {e}")

# 注册退出清理函数
atexit.register(cleanup_tcpdump)

class CaptureThread(QThread):
    packet_received = Signal(str)
    stopped = Signal()

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.running = True
        self.process = None

    def run(self):
        try:
            command = [
                tcpdump_temp_path,
                "-i", self.interface,
                "-nve",
                "ether", "proto", "0x88cc",
                "-A",
                "-s0",
                "-t"
            ]
            print(command)
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW  # 隐藏控制台窗口
            )
            while self.running and self.process.poll() is None:
                output = self.process.stdout.readline()
                if output:
                    self.packet_received.emit(output.strip())
        except Exception as e:
            self.packet_received.emit(f"ERROR: {str(e)}")
        finally:
            if self.process:
                self.process.terminate()
                self.process.wait()  # 确保进程完全终止
            self.stopped.emit()

    def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()
            self.process.wait()  # 确保进程完全终止

class PacketAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.capture_thread = None
        self.init_ui()
        self.load_interfaces()

        # 设置窗口图标
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network.ico")
            self.setWindowIcon(QIcon(icon_path))
        except Exception as e:
            print(f"加载图标文件时出错: {e}")

    def init_ui(self):
        self.setWindowTitle("链路层发现协议分析程序2025.2.1")
        self.setGeometry(100, 100, 800, 600)

        main_widget = QWidget()
        main_layout = QVBoxLayout()

        interface_layout = QHBoxLayout()
        self.interface_combo = QComboBox()
        interface_layout.addWidget(QLabel("选择网络接口:"))
        interface_layout.addWidget(self.interface_combo)
        self.refresh_btn = QPushButton("刷新接口")
        self.refresh_btn.clicked.connect(self.load_interfaces)
        interface_layout.addWidget(self.refresh_btn)
        self.clear_data_btn = QPushButton("清空数据")
        self.clear_data_btn.clicked.connect(self.clear_data)
        interface_layout.addWidget(self.clear_data_btn)
        main_layout.addLayout(interface_layout)

        self.selected_interface_label = QLabel("当前选择的接口: 无")
        main_layout.addWidget(self.selected_interface_label)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("? 开始捕获")
        self.start_btn.clicked.connect(self.toggle_capture)
        self.stop_btn = QPushButton("? 停止捕获")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        main_layout.addLayout(btn_layout)

        # 设置 QTreeWidget 的样式
        self.result_tree = QTreeWidget()
        self.result_tree.setHeaderLabels(["字段", "值"])
        self.result_tree.setColumnWidth(0, 200)
        self.result_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.result_tree.customContextMenuRequested.connect(self.show_context_menu)
        self.result_tree.setStyleSheet("QTreeWidget { border: 2px solid black; }")
        main_layout.addWidget(self.result_tree)

        # 在 QTreeWidget 和 QTextEdit 之间添加标题栏
        title_label = QLabel("LLDP数据实时捕获窗口")
        title_label.setStyleSheet("font-size: 13px;")
        main_layout.addWidget(title_label)

        # 设置 QTextEdit 的样式
        self.packet_display = QTextEdit()
        self.packet_display.setReadOnly(True)
        self.packet_display.setLineWrapMode(QTextEdit.WidgetWidth)
        self.packet_display.setStyleSheet("QTextEdit { border: 2px solid black; }")
        main_layout.addWidget(self.packet_display)

        # 状态信息和作者信息
        status_layout = QHBoxLayout()
        self.status_label = QLabel("就绪 | 请选择网络接口后开始捕获")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch(1)  # 添加弹性空间，使标签靠右对齐
        self.powered_by_label = QLabel("Powered by Six.Xue@outlook.com")
        status_layout.addWidget(self.powered_by_label)
        main_layout.addLayout(status_layout)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # 设置窗口关闭时自动停止捕获
        self.closeEvent = self.on_close

    def load_interfaces(self):
        self.interface_combo.clear()
        interfaces = self.get_tcpdump_interfaces()
        valid_count = 0
        for iface in interfaces:
            display_name = f"{iface['description']} ({iface['device']})"
            self.interface_combo.addItem(display_name, iface['device'])
            valid_count += 1
        if valid_count > 0:
            self.status_label.setText(f"找到 {valid_count} 个可用接口 | 最后更新: {datetime.now().strftime('%H:%M:%S')}")

    def get_tcpdump_interfaces(self):
        try:
            result = subprocess.run(
                [tcpdump_temp_path, "-D"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW  # 添加此行以隐藏控制台窗口
            )
            if result.returncode != 0:
                print("Error executing tcpdump.exe -D:")
                print(result.stderr.strip())
                return []
            interfaces = []
            in_interfaces_section = False
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("1."):
                    in_interfaces_section = True
                if in_interfaces_section:
                    if line.startswith("**********************************"):
                        in_interfaces_section = False
                    else:
                        match = re.match(r"(\d+)\.(.*?)\s+\((.*?)\)$", line, re.DOTALL)
                        if match:
                            interface_info = {
                                "number": match.group(1),
                                "device": match.group(2).strip(),
                                "description": match.group(3).strip()
                            }
                            interfaces.append(interface_info)
            return interfaces
        except Exception as e:
            print(f"An error occurred: {e}")
            return []

    def toggle_capture(self):
        if self.capture_thread and self.capture_thread.isRunning():
            return
        if self.interface_combo.currentIndex() == -1:
            QMessageBox.warning(self, "警告", "请先选择网络接口！")
            return
        interface = self.interface_combo.currentData()
        self.selected_interface_label.setText(f"当前选择的接口: {self.interface_combo.currentText()}")
        self.capture_thread = CaptureThread(interface)
        self.capture_thread.packet_received.connect(self.process_packet)
        self.capture_thread.stopped.connect(self.capture_stopped)
        self.capture_thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText(f"正在捕获来自 {interface} 的报文...")

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.status_label.setText("正在停止捕获...")

    def capture_stopped(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("捕获已停止")

    def process_packet(self, line):
        self.packet_display.append(line)
        self.update_result_tree(line)

    def update_result_tree(self, line):
        field_order = [
            "端口描述", "VLAN", "存活时间", "系统名称", "Chassis ID",
            "管理IP地址", "管理MAC地址", "型号名称", "序列号", "软件版本"
        ]
        root = self.result_tree.invisibleRootItem()
        lldp_item = None
        for i in range(root.childCount()):
            if root.child(i).text(0) == "LLDP 数据包":
                lldp_item = root.child(i)
                break
        if not lldp_item:
            lldp_item = QTreeWidgetItem(root, ["LLDP 数据包"])
            for field in field_order:
                lldp_item.addChild(QTreeWidgetItem([field, ""]))
            self.result_tree.expandAll()

        if "Port Description TLV (4)" in line:
            parts = line.split(': ')
            if len(parts) >= 2:
                self.set_field_value(lldp_item, "端口描述", parts[1])
        elif "port vlan id (PVID)" in line:
            match = re.search(r"port vlan id \(PVID\): (\d+)", line)
            if match:
                self.set_field_value(lldp_item, "VLAN", match.group(1))
        elif "Time to Live TLV (3)" in line:
            value = re.search(r"TTL (\d+)s", line)
            if value:
                self.set_field_value(lldp_item, "存活时间", f"{value.group(1)} 秒")
        elif "System Name TLV (5)" in line:
            parts = line.split(': ')
            if len(parts) >= 2:
                self.set_field_value(lldp_item, "系统名称", parts[1])
        elif "Subtype MAC address (4):" in line:
            value = re.search(r"Subtype MAC address \(4\): (\S+)", line)
            if value:
                self.set_field_value(lldp_item, "Chassis ID", value.group(1))
        elif "Management Address length 5, AFI IPv4 (1):" in line:
            match = re.search(r"Management Address length \d+, AFI IPv4 \(1\): ([\d.]+)", line)
            if match:
                self.set_field_value(lldp_item, "管理IP地址", match.group(1))
        elif "Management Address length 7, AFI 802 (6)" in line:
            match = re.search(r"Management Address length \d+, AFI 802 \(6\): ([\da-fA-F:]+)", line)
            if match:
                self.set_field_value(lldp_item, "管理MAC地址", match.group(1))
        elif "Model name" in line:
            match = re.search(r"Model name\s+(.*)", line)
            if match:
                self.set_field_value(lldp_item, "型号名称", match.group(1))
        elif "Serial number" in line:
            match = re.search(r"Serial number\s+(\S+)", line)
            if match:
                self.set_field_value(lldp_item, "序列号", match.group(1))
        elif "Software revision" in line:
            match = re.search(r"Software revision\s+(.*)", line)
            if match:
                self.set_field_value(lldp_item, "软件版本", match.group(1))

    def set_field_value(self, lldp_item, field, value):
        for i in range(lldp_item.childCount()):
            if lldp_item.child(i).text(0) == field:
                lldp_item.child(i).setText(1, value)
                break

    def show_context_menu(self, position):
        menu = QMenu(self)
        copy_action = QAction("复制值", self)
        copy_action.triggered.connect(self.copy_value)
        menu.addAction(copy_action)
        menu.exec(self.result_tree.viewport().mapToGlobal(position))

    def copy_value(self):
        current_item = self.result_tree.currentItem()
        if current_item and current_item.columnCount() > 1:
            value = current_item.text(1)
            QApplication.clipboard().setText(value)
            QMessageBox.information(self, "复制成功", f"已复制: {value}")

    def clear_data(self):
        root = self.result_tree.invisibleRootItem()
        for i in range(root.childCount()):
            child = root.child(i)
            if child.text(0) == "LLDP 数据包":
                for j in range(child.childCount()):
                    existing_field_item = child.child(j)
                    existing_field_item.setText(1, "")
        self.packet_display.clear()

    def on_close(self, event):
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
        event.accept()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_current_executable_path():
    dll = ctypes.WinDLL('kernel32')
    GetModuleHandle = dll.GetModuleHandleW
    GetModuleHandle.restype = wintypes.HMODULE
    GetModuleHandle.argtypes = [wintypes.LPCWSTR]

    GetModuleFileName = dll.GetModuleFileNameW
    GetModuleFileName.restype = wintypes.DWORD
    GetModuleFileName.argtypes = [
        wintypes.HMODULE,
        wintypes.LPWSTR,
        wintypes.DWORD
    ]

    buffer_size = 1024
    buffer = ctypes.create_unicode_buffer(buffer_size)

    h_module = GetModuleHandle(None)
    if h_module == 0:
        raise ctypes.WinError()

    length = GetModuleFileName(h_module, buffer, buffer_size)
    if length == 0:
        raise ctypes.WinError()

    return buffer.value

def run_as_admin():
    try:
        current_path = get_current_executable_path()
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            current_path,
            None,
            None,
            1
        )
    except Exception as e:
        print(f"Error running as admin: {e}")
        QMessageBox.critical(None, "权限错误", "无法以管理员权限运行程序！")
        sys.exit(1)

if __name__ == "__main__":
    deploy_tcpdump()
    if not is_admin():
        print("当前用户没有管理员权限，尝试以管理员权限重新运行...")
        run_as_admin()
        sys.exit(0)
    else:
        print("当前用户具有管理员权限，继续运行程序...")
        app = QApplication(sys.argv)
        window = PacketAnalyzerGUI()
        window.show()
        sys.exit(app.exec())