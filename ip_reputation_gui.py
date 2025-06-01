import sys
import json
import re
import os
import csv
import time
import platform
import datetime
import requests
import ipaddress
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget, 
                            QTableWidgetItem, QTabWidget, QComboBox, QGroupBox, QGridLayout,
                            QMessageBox, QSplitter, QFileDialog, QCheckBox, QFrame, QProgressBar,
                            QStatusBar, QInputDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings, QDate
from PyQt5.QtGui import QFont, QColor, QPixmap, QIcon

class ApiThread(QThread):
    """用于在后台线程中调用API的类"""
    result_signal = pyqtSignal(dict, str)  # 传递结果和对应的IP
    error_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)  # 当前进度, 总数
    limit_reached_signal = pyqtSignal(str)  # API限制提示信息
    json_signal = pyqtSignal(dict, str)  # 原始JSON信号
    
    def __init__(self, api_key, ip_addresses, lang="zh"):
        super().__init__()
        self.api_key = api_key
        self.ip_addresses = ip_addresses.split(',')
        self.lang = lang
        self.stop_flag = False
        
    def stop(self):
        """停止查询"""
        self.stop_flag = True
        
    def run(self):
        try:
            total_ips = len(self.ip_addresses)
            processed_ips = 0
            
            # 逐个处理IP
            for ip in self.ip_addresses:
                if self.stop_flag:
                    break
                    
                ip = ip.strip()
                if not ip:
                    continue
                
                url = "https://api.threatbook.cn/v3/scene/ip_reputation"
                params = {
                    "apikey": self.api_key,
                    "resource": ip,
                    "lang": self.lang
                }
                
                # 发送请求
                response = requests.get(url, params=params)
                result = response.json()
                
                # 发送原始JSON信号
                self.json_signal.emit(result, ip)
                
                if result.get("response_code") == 0 and "data" in result:
                    # 发送结果信号
                    self.result_signal.emit(result, ip)
                elif result.get("response_code") == 2:
                    # API调用次数限制
                    self.limit_reached_signal.emit(f"API调用超出次数限制: {result.get('verbose_msg')}")
                    break
                else:
                    # 其他错误
                    self.error_signal.emit(f"查询IP {ip} 错误: {result.get('verbose_msg', '未知错误')}")
                
                # 更新进度
                processed_ips += 1
                self.progress_signal.emit(processed_ips, total_ips)
                
                # 每次查询间隔一点时间，避免API限制
                time.sleep(0.5)
                
        except Exception as e:
            self.error_signal.emit(f"请求出错: {str(e)}")

def is_private_ip(ip):
    """检查IP是否为内网地址"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def extract_ips(text):
    """从文本中提取有效的公网IP地址（去重和过滤内网IP）"""
    # IP地址正则表达式
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    # 找出所有可能的IP地址
    potential_ips = re.findall(ip_pattern, text)
    
    # 验证IP地址并过滤掉内网IP
    valid_ips = []
    for ip in potential_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            # 排除内网IP和广播地址等
            if not ip_obj.is_private and not ip_obj.is_multicast and not ip_obj.is_loopback and not ip_obj.is_reserved:
                valid_ips.append(ip)
        except ValueError:
            # 无效IP格式
            continue
    
    # 去重
    unique_ips = list(dict.fromkeys(valid_ips))
    return unique_ips

class IPReputationApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP信誉查询工具")
        self.setMinimumSize(1000, 700)
        
        # 检测操作系统并设置样式
        self.is_mac = platform.system() == "Darwin"
        
        # 设置图标（如果有的话）
        self.setWindowIcon(QIcon("icon.png"))
        
        # 创建配置对象
        self.settings = QSettings("IPReputation", "Settings")
        
        # 创建主窗口部件
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # 创建主布局
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # 创建配置区域
        self.create_config_section()
        
        # 创建查询区域
        self.create_query_section()
        
        # 创建显示结果区域
        self.create_results_section()
        
        # 创建状态栏
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("准备就绪")
        
        # 存储查询结果
        self.current_results = {"data": {}}
        
        # 当前查询线程
        self.api_thread = None
        
        # 检查是否是新的一天，如果是则重置查询计数
        self.check_and_reset_daily_count()
        
        # 加载保存的API密钥
        self.load_api_key()
    
    def check_and_reset_daily_count(self):
        """检查是否是新的一天，如果是则重置查询计数"""
        # 获取当前日期
        current_date = QDate.currentDate().toString(Qt.ISODate)
        
        # 获取上次查询的日期
        last_query_date = self.settings.value("last_query_date", "")
        
        # 如果日期不同，重置计数
        if current_date != last_query_date:
            self.settings.setValue("daily_query_count", 0)
            self.settings.setValue("last_query_date", current_date)
        
        # 更新当日查询总数显示
        self.update_daily_count_display()
    
    def create_config_section(self):
        config_group = QGroupBox("配置")
        config_layout = QHBoxLayout()
        
        # API密钥输入
        api_key_label = QLabel("API密钥:")
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("请输入您的API密钥")
        self.api_key_input.setEchoMode(QLineEdit.Password)
        
        # 记住API密钥复选框
        self.remember_api_key = QCheckBox("记住API密钥")
        self.remember_api_key.setChecked(True)
        
        # 语言选择
        lang_label = QLabel("语言:")
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(["中文", "英文"])
        
        # 添加到布局
        config_layout.addWidget(api_key_label)
        config_layout.addWidget(self.api_key_input, 3)
        config_layout.addWidget(self.remember_api_key)
        config_layout.addWidget(lang_label)
        config_layout.addWidget(self.lang_combo, 1)
        
        config_group.setLayout(config_layout)
        self.main_layout.addWidget(config_group)
    
    def create_query_section(self):
        query_group = QGroupBox("IP查询")
        query_layout = QVBoxLayout()
        
        # IP输入区域 - 使用水平布局
        ip_layout = QHBoxLayout()
        
        # IP输入标签
        ip_label = QLabel("IP地址:")
        ip_layout.addWidget(ip_label)
        
        # IP输入框 - 较小的文本输入区域
        self.ip_input = QTextEdit()
        self.ip_input.setPlaceholderText("输入单个IP或多个IP(每行一个IP或逗号分隔，会自动提取有效IP并去除内网地址)")
        self.ip_input.setMaximumHeight(80)  # 设置最大高度
        ip_layout.addWidget(self.ip_input, 3)  # 占比3
        
        # 创建按钮垂直布局
        button_vlayout = QVBoxLayout()
        
        # 处理IP按钮
        self.process_button = QPushButton("处理IP")
        self.process_button.clicked.connect(self.process_ips)
        self.process_button.setMinimumWidth(80)
        button_vlayout.addWidget(self.process_button)
        
        # 导入文件按钮
        self.import_button = QPushButton("导入文件")
        self.import_button.clicked.connect(self.import_file)
        self.import_button.setMinimumWidth(80)
        button_vlayout.addWidget(self.import_button)
        
        # 查询按钮
        self.query_button = QPushButton("查询")
        self.query_button.clicked.connect(self.query_ip)
        self.query_button.setMinimumWidth(80)
        button_vlayout.addWidget(self.query_button)
        
        # 将按钮布局添加到IP区域布局
        ip_layout.addLayout(button_vlayout)
        
        # 添加IP输入区域到主查询布局
        query_layout.addLayout(ip_layout)
        
        # IP计数和操作区域 - 水平布局
        count_controls_layout = QHBoxLayout()
        
        # IP数量和查询总数区域 - 左侧
        count_layout = QHBoxLayout()
        
        # IP数量显示
        self.ip_count_label = QLabel("IP数量: 0")
        self.ip_count_label.setStyleSheet("color: blue;")
        count_layout.addWidget(self.ip_count_label)
        
        # 当日查询总数显示
        self.daily_count_label = QLabel("今日查询总数: 0")
        self.daily_count_label.setStyleSheet("color: purple; font-weight: bold;")
        count_layout.addWidget(self.daily_count_label)
        
        # 添加到左侧
        count_controls_layout.addLayout(count_layout)
        count_controls_layout.addStretch()
        
        # 右侧区域 - 进度标签、进度条和操作按钮
        right_controls = QHBoxLayout()
        
        # 进度描述标签
        self.progress_label = QLabel("查询进度:")
        right_controls.addWidget(self.progress_label)
        
        # 查询进度条 - 小而细的样式
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v/%m")
        self.progress_bar.setMaximumWidth(150)  # 限制宽度
        self.progress_bar.setMaximumHeight(15)  # 限制高度
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid grey;
                border-radius: 3px;
                text-align: center;
                background-color: #f0f0f0;
            }
            
            QProgressBar::chunk {
                background-color: #4CAF50;
                margin: 0px;
            }
        """)
        right_controls.addWidget(self.progress_bar)
        
        # 操作按钮
        # 清除按钮
        self.clear_button = QPushButton("清除")
        self.clear_button.clicked.connect(self.clear_results)
        self.clear_button.setMaximumWidth(60)  # 设置最大宽度
        self.clear_button.setMaximumHeight(22)  # 设置最大高度
        right_controls.addWidget(self.clear_button)
        
        # 停止按钮
        self.stop_button = QPushButton("停止")
        self.stop_button.clicked.connect(self.stop_query)
        self.stop_button.setMaximumWidth(60)  # 设置最大宽度
        self.stop_button.setMaximumHeight(22)  # 设置最大高度
        self.stop_button.setEnabled(False)
        right_controls.addWidget(self.stop_button)
        
        # 导出按钮
        self.export_button = QPushButton("导出")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setMaximumWidth(60)  # 设置最大宽度
        self.export_button.setMaximumHeight(22)  # 设置最大高度
        self.export_button.setEnabled(False)  # 初始时禁用
        right_controls.addWidget(self.export_button)
        
        # 添加右侧控件到布局
        count_controls_layout.addLayout(right_controls)
        
        # 添加计数和控制区域到主布局
        query_layout.addLayout(count_controls_layout)
        
        query_group.setLayout(query_layout)
        self.main_layout.addWidget(query_group)
    
    def create_results_section(self):
        # 创建选项卡窗口
        self.result_tabs = QTabWidget()
        
        # 创建统计选项卡
        self.stats_tab = QWidget()
        stats_layout = QVBoxLayout(self.stats_tab)
        
        # 统计信息区域 - 第一行布局
        stats_layout_row1 = QHBoxLayout()
        stats_layout_row1.setAlignment(Qt.AlignLeft)
        
        # 总IP数
        self.total_ips_label = QLabel("总IP数: 0")
        self.total_ips_label.setStyleSheet("font-size: 14px;")
        stats_layout_row1.addWidget(self.total_ips_label)
        
        # 分隔符
        stats_layout_row1.addWidget(QLabel("|"))
        
        # 恶意IP数
        self.malicious_ips_label = QLabel("恶意IP数: 0")
        self.malicious_ips_label.setStyleSheet("font-size: 14px; color: red;")
        self.malicious_ips_label.setCursor(Qt.PointingHandCursor)
        self.malicious_ips_label.mouseReleaseEvent = lambda event: self.filter_by_category("is_malicious", True)
        stats_layout_row1.addWidget(self.malicious_ips_label)
        
        # 分隔符
        stats_layout_row1.addWidget(QLabel("|"))
        
        # 安全IP数
        self.safe_ips_label = QLabel("安全IP数: 0")
        self.safe_ips_label.setStyleSheet("font-size: 14px; color: green;")
        self.safe_ips_label.setCursor(Qt.PointingHandCursor)
        self.safe_ips_label.mouseReleaseEvent = lambda event: self.filter_by_category("is_malicious", False)
        stats_layout_row1.addWidget(self.safe_ips_label)
        
        # 分隔符
        stats_layout_row1.addWidget(QLabel("|"))
        
        # 可信度分布
        self.confidence_label = QLabel("可信度分布: ")
        self.confidence_label.setStyleSheet("font-size: 14px;")
        stats_layout_row1.addWidget(self.confidence_label)
        
        # 高可信度
        self.confidence_high_label = QLabel("高(0)")
        self.confidence_high_label.setStyleSheet("font-size: 14px; color: #e74c3c;")
        self.confidence_high_label.setCursor(Qt.PointingHandCursor)
        self.confidence_high_label.mouseReleaseEvent = lambda event: self.filter_by_category("confidence", "high")
        stats_layout_row1.addWidget(self.confidence_high_label)
        
        # 中可信度
        self.confidence_medium_label = QLabel("中(0)")
        self.confidence_medium_label.setStyleSheet("font-size: 14px; color: #f39c12;")
        self.confidence_medium_label.setCursor(Qt.PointingHandCursor)
        self.confidence_medium_label.mouseReleaseEvent = lambda event: self.filter_by_category("confidence", "medium")
        stats_layout_row1.addWidget(self.confidence_medium_label)
        
        # 低可信度
        self.confidence_low_label = QLabel("低(0)")
        self.confidence_low_label.setStyleSheet("font-size: 14px; color: #3498db;")
        self.confidence_low_label.setCursor(Qt.PointingHandCursor)
        self.confidence_low_label.mouseReleaseEvent = lambda event: self.filter_by_category("confidence", "low")
        stats_layout_row1.addWidget(self.confidence_low_label)
        
        # 分隔符
        stats_layout_row1.addWidget(QLabel("|"))
        
        # 地区分布
        self.location_label = QLabel("地区分布: ")
        self.location_label.setStyleSheet("font-size: 14px;")
        stats_layout_row1.addWidget(self.location_label)
        
        # 省内IP
        self.anhui_ips_label = QLabel("安徽(0)")
        self.anhui_ips_label.setStyleSheet("font-size: 14px; color: #27ae60;")
        self.anhui_ips_label.setCursor(Qt.PointingHandCursor)
        self.anhui_ips_label.mouseReleaseEvent = lambda event: self.filter_by_category("location", "anhui")
        stats_layout_row1.addWidget(self.anhui_ips_label)
        
        # 中国其他省份IP
        self.china_other_ips_label = QLabel("中国其他(0)")
        self.china_other_ips_label.setStyleSheet("font-size: 14px; color: #2980b9;")
        self.china_other_ips_label.setCursor(Qt.PointingHandCursor)
        self.china_other_ips_label.mouseReleaseEvent = lambda event: self.filter_by_category("location", "china_other")
        stats_layout_row1.addWidget(self.china_other_ips_label)
        
        # 国外IP
        self.foreign_ips_label = QLabel("国外(0)")
        self.foreign_ips_label.setStyleSheet("font-size: 14px; color: #8e44ad;")
        self.foreign_ips_label.setCursor(Qt.PointingHandCursor)
        self.foreign_ips_label.mouseReleaseEvent = lambda event: self.filter_by_category("location", "foreign")
        stats_layout_row1.addWidget(self.foreign_ips_label)
        
        # 添加第一行统计
        stats_layout.addLayout(stats_layout_row1)
        
        # 添加分隔线
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        stats_layout.addWidget(line)
        
        # 统计信息区域 - 第二行布局
        stats_layout_row2 = QHBoxLayout()
        stats_layout_row2.setAlignment(Qt.AlignLeft)
        
        # 运营商分布
        carrier_container = QHBoxLayout()
        carrier_container.setAlignment(Qt.AlignLeft)
        carrier_container.setSpacing(0)  # 减少间距
        carrier_container.setContentsMargins(0, 0, 0, 0)  # 移除边距
        
        self.carrier_label = QLabel("运营商: ")
        self.carrier_label.setStyleSheet("font-size: 14px;")
        carrier_container.addWidget(self.carrier_label)
        
        # 运营商统计容器
        self.carrier_labels_layout = QHBoxLayout()
        self.carrier_labels_layout.setAlignment(Qt.AlignLeft)
        self.carrier_labels_layout.setSpacing(0)  # 减少间距
        self.carrier_labels_layout.setContentsMargins(0, 0, 0, 0)  # 移除边距
        self.carrier_labels = {}  # 存储运营商标签的字典
        carrier_container.addLayout(self.carrier_labels_layout)
        
        stats_layout_row2.addLayout(carrier_container)
        
        # 分隔符
        stats_layout_row2.addWidget(QLabel("|"))
        
        # 判定类型分布
        judgment_container = QHBoxLayout()
        judgment_container.setAlignment(Qt.AlignLeft)
        judgment_container.setSpacing(0)  # 减少间距
        judgment_container.setContentsMargins(0, 0, 0, 0)  # 移除边距
        
        self.judgment_label = QLabel("判定类型: ")
        self.judgment_label.setStyleSheet("font-size: 14px;")
        judgment_container.addWidget(self.judgment_label)
        
        # 判定类型统计容器
        self.judgment_labels_layout = QHBoxLayout()
        self.judgment_labels_layout.setAlignment(Qt.AlignLeft)
        self.judgment_labels_layout.setSpacing(0)  # 减少间距
        self.judgment_labels_layout.setContentsMargins(0, 0, 0, 0)  # 移除边距
        self.judgment_labels = {}  # 存储判定类型标签的字典
        judgment_container.addLayout(self.judgment_labels_layout)
        
        stats_layout_row2.addLayout(judgment_container)
        
        # 添加第二行统计
        stats_layout.addLayout(stats_layout_row2)
        
        # 表格操作按钮区域
        table_controls = QHBoxLayout()
        
        # 重置过滤按钮
        self.reset_filter_button = QPushButton("重置过滤")
        self.reset_filter_button.clicked.connect(self.reset_filter)
        table_controls.addWidget(self.reset_filter_button)
        
        # 仅显示恶意IP按钮
        self.show_malicious_only = QCheckBox("仅显示恶意IP")
        self.show_malicious_only.stateChanged.connect(self.filter_table)
        table_controls.addWidget(self.show_malicious_only)
        
        # 排序类型下拉框
        self.sort_label = QLabel("排序方式:")
        table_controls.addWidget(self.sort_label)
        
        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["IP地址", "是否恶意", "可信度", "严重程度", "地理位置", "运营商"])
        self.sort_combo.currentIndexChanged.connect(self.sort_table)
        table_controls.addWidget(self.sort_combo)
        
        # 添加排序方向
        self.sort_direction = QComboBox()
        self.sort_direction.addItems(["升序", "降序"])
        self.sort_direction.currentIndexChanged.connect(self.sort_table)
        table_controls.addWidget(self.sort_direction)
        
        # 复制选中IP按钮
        self.copy_button = QPushButton("复制选中IP")
        self.copy_button.clicked.connect(self.copy_selected_ip)
        table_controls.addWidget(self.copy_button)
        
        # 导出当前视图按钮
        self.export_view_button = QPushButton("导出当前视图")
        self.export_view_button.clicked.connect(self.export_current_view)
        table_controls.addWidget(self.export_view_button)
        
        stats_layout.addLayout(table_controls)
        
        # 创建结果表格
        self.overview_table = QTableWidget()
        self.overview_table.setColumnCount(7)
        self.overview_table.setHorizontalHeaderLabels(["IP地址", "是否恶意", "可信度", "严重程度", "地理位置", "运营商", "判定类型"])
        self.overview_table.horizontalHeader().setStretchLastSection(True)
        self.overview_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.overview_table.cellClicked.connect(self.show_ip_details)
        self.overview_table.setSortingEnabled(True)  # 启用排序
        # 美化表格
        self.overview_table.setAlternatingRowColors(True)
        self.overview_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #d0d0d0;
                selection-background-color: #a6c9e2;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 5px;
                border: 1px solid #d0d0d0;
                font-weight: bold;
            }
            QTableWidget::item:alternate {
                background-color: #f9f9f9;
            }
        """)
        
        stats_layout.addWidget(self.overview_table)
        self.result_tabs.addTab(self.stats_tab, "概览与统计")
        
        # 创建详情选项卡
        self.details_tab = QWidget()
        details_layout = QVBoxLayout(self.details_tab)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        
        details_layout.addWidget(self.details_text)
        self.result_tabs.addTab(self.details_tab, "详情")
        
        # 创建原始JSON选项卡
        self.json_tab = QWidget()
        json_layout = QVBoxLayout(self.json_tab)
        
        # JSON操作按钮
        json_controls = QHBoxLayout()
        
        # 复制JSON按钮
        self.copy_json_button = QPushButton("复制JSON")
        self.copy_json_button.clicked.connect(self.copy_json)
        json_controls.addWidget(self.copy_json_button)
        
        # 清除JSON按钮
        self.clear_json_button = QPushButton("清除")
        self.clear_json_button.clicked.connect(lambda: self.json_text.clear())
        json_controls.addWidget(self.clear_json_button)
        
        json_controls.addStretch()
        
        json_layout.addLayout(json_controls)
        
        # JSON显示区域
        self.json_text = QTextEdit()
        self.json_text.setReadOnly(True)
        self.json_text.setFont(QFont("Courier New", 10))
        
        json_layout.addWidget(self.json_text)
        self.result_tabs.addTab(self.json_tab, "原始JSON")
        
        self.main_layout.addWidget(self.result_tabs, 1)
    
    def update_daily_count_display(self):
        """更新当日查询总数显示"""
        daily_count = int(self.settings.value("daily_query_count", 0))
        self.daily_count_label.setText(f"今日查询总数: {daily_count}")
    
    def process_ips(self):
        """处理输入框中的IP，提取、去重、过滤内网IP并显示在原输入框"""
        input_text = self.ip_input.toPlainText()
        
        # 提取有效IP
        valid_ips = extract_ips(input_text)
        
        # 显示处理后的IP
        if valid_ips:
            # 在原输入框中更新IP列表（以逗号分隔）
            self.ip_input.setText(", ".join(valid_ips))
            
            # 更新IP数量显示
            self.ip_count_label.setText(f"IP数量: {len(valid_ips)}")
            
            self.status_bar.showMessage(f"成功提取 {len(valid_ips)} 个有效公网IP")
        else:
            self.ip_input.clear()
            self.ip_count_label.setText("IP数量: 0")
            self.status_bar.showMessage("未找到有效公网IP")
    
    def query_ip(self):
        # 先处理IP
        self.process_ips()
        
        # 获取处理后的IP
        ip_addresses = self.ip_input.toPlainText().strip()
        
        # 获取API密钥
        api_key = self.api_key_input.text().strip()
        
        # 验证输入
        if not api_key:
            QMessageBox.warning(self, "警告", "请输入API密钥")
            return
            
        if not ip_addresses:
            QMessageBox.warning(self, "警告", "未找到有效的公网IP地址")
            return
        
        # 保存API密钥
        if self.remember_api_key.isChecked():
            self.settings.setValue("api_key", api_key)
        
        # 设置语言
        lang = "zh" if self.lang_combo.currentText() == "中文" else "en"
        
        # 更新状态栏
        self.status_bar.showMessage("正在查询中...")
        
        # 禁用查询按钮，启用停止按钮
        self.query_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # 设置进度条
        self.progress_bar.setValue(0)
        
        # 清空当前结果
        self.current_results = {"data": {}}
        self.overview_table.setRowCount(0)
        self.details_text.clear()
        self.json_text.clear()
        self.update_statistics()
        
        # 更新当日查询计数
        daily_count = int(self.settings.value("daily_query_count", 0))
        daily_count += len(ip_addresses.split(','))
        self.settings.setValue("daily_query_count", daily_count)
        self.update_daily_count_display()
        
        # 创建并启动线程
        self.api_thread = ApiThread(api_key, ip_addresses, lang)
        self.api_thread.result_signal.connect(self.add_result)
        self.api_thread.error_signal.connect(self.show_error)
        self.api_thread.progress_signal.connect(self.update_progress)
        self.api_thread.limit_reached_signal.connect(self.show_limit_warning)
        self.api_thread.json_signal.connect(self.update_json_display)
        self.api_thread.finished.connect(self.query_finished)
        self.api_thread.start()
    
    def update_json_display(self, result, ip):
        """更新JSON显示"""
        # 调试输出 - 查看完整JSON数据
        print(f"\n======= 原始JSON数据（IP: {ip}）=======")
        print(json.dumps(result, indent=4, ensure_ascii=False))
        print("=" * 50)
        
        # 添加IP信息到JSON显示
        pretty_json = json.dumps(result, indent=4, ensure_ascii=False)
        current_text = self.json_text.toPlainText()
        
        # 强制设置JSON文本到文本区域
        if current_text:
            # 如果已有内容，添加分隔符
            new_content = current_text + "\n\n" + "-" * 40 + f"\nIP: {ip}\n" + "-" * 40 + "\n" + pretty_json
            self.json_text.setText(new_content)
        else:
            # 第一个结果
            new_content = f"IP: {ip}\n" + "-" * 40 + "\n" + pretty_json
            self.json_text.setText(new_content)
        
        # 强制刷新显示
        self.json_text.repaint()
        self.json_tab.repaint()
        
        # 调试输出
        print(f"JSON显示已更新，长度: {len(new_content)}")
        if "data" in result and ip in result["data"]:
            print(f"JSON data contains information for IP: {ip}")
        else:
            print(f"No data in JSON for IP: {ip}")
    
    def add_result(self, result, ip):
        """添加单个IP的查询结果"""
        print(f"\n===== 正在处理IP结果: {ip} =====")
        print(f"Response code: {result.get('response_code')}")
        
        # 首先检查基本结构
        if "data" not in result:
            print(f"Error: 响应中没有'data'字段")
            print(f"Full response keys: {list(result.keys())}")
            self.show_error(f"IP {ip} 查询响应结构异常")
            return
            
        if ip not in result["data"]:
            print(f"Error: IP '{ip}' 不在响应的data中")
            print(f"Data keys: {list(result['data'].keys()) if isinstance(result['data'], dict) else 'Not a dict'}")
            self.show_error(f"IP {ip} 数据缺失")
            return
            
        try:
            # 添加到当前结果集
            self.current_results["data"][ip] = result["data"][ip]
            
            # 更新表格
            row = self.overview_table.rowCount()
            self.overview_table.setRowCount(row + 1)
            
            data = result["data"][ip]
            
            # 调试 - 打印关键数据
            print(f"Processing IP: {ip}")
            print(f"Available fields: {list(data.keys())}")
            print(f"Is malicious: {data.get('is_malicious', False)}")
            print(f"Confidence: {data.get('confidence_level', '')}")
            print(f"Severity: {data.get('severity', '')}")
            print(f"Basic info: {data.get('basic', {})}")
            
            # IP地址
            ip_item = QTableWidgetItem(ip)
            self.overview_table.setItem(row, 0, ip_item)
            
            # 是否恶意
            is_malicious = data.get("is_malicious", False)
            malicious_item = QTableWidgetItem("是" if is_malicious else "否")
            malicious_item.setForeground(QColor("red" if is_malicious else "green"))
            malicious_item.setTextAlignment(Qt.AlignCenter)
            self.overview_table.setItem(row, 1, malicious_item)
            
            # 可信度
            confidence_map = {"low": "低", "medium": "中", "high": "高"}
            confidence = data.get("confidence_level", "")
            # 显示中文，保存英文
            confidence_text = confidence_map.get(confidence, confidence)
            confidence_item = QTableWidgetItem(confidence_text)
            confidence_item.setData(Qt.UserRole, confidence)  # 保存原始英文值
            print(f"保存可信度: 显示={confidence_text}, 原始={confidence}")
            confidence_item.setTextAlignment(Qt.AlignCenter)
            self.overview_table.setItem(row, 2, confidence_item)
            
            # 严重程度
            severity_map = {"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "无危胁"}
            severity = data.get("severity", "")
            severity_text = severity_map.get(severity, severity)
            severity_item = QTableWidgetItem(severity_text)
            severity_item.setTextAlignment(Qt.AlignCenter)
            self.overview_table.setItem(row, 3, severity_item)
            
            # 地理位置
            location = ""
            try:
                if "basic" in data and "location" in data["basic"]:
                    loc = data["basic"]["location"]
                    country = loc.get('country', '')
                    province = loc.get('province', '')
                    city = loc.get('city', '')
                    location = f"{country}"
                    if province:
                        location += f" {province}"
                    if city and city != province:
                        location += f" {city}"
                print(f"地理位置信息: {location}")
            except Exception as e:
                print(f"Error processing location: {str(e)}")
                print(f"Basic data: {data.get('basic', {})}")
                
            self.overview_table.setItem(row, 4, QTableWidgetItem(location))
            
            # 运营商
            carrier = ""
            try:
                carrier = data.get("basic", {}).get("carrier", "")
                print(f"运营商信息: {carrier}")
            except Exception as e:
                print(f"Error processing carrier: {str(e)}")
                
            carrier_item = QTableWidgetItem(carrier)
            self.overview_table.setItem(row, 5, carrier_item)
            
            # 判定类型
            judgments = ""
            try:
                judgments = ", ".join(data.get("judgments", []))
                print(f"判定类型信息: {judgments}")
            except Exception as e:
                print(f"Error processing judgments: {str(e)}")
                
            judgments_item = QTableWidgetItem(judgments)
            self.overview_table.setItem(row, 6, judgments_item)
            
            # 强制重绘表格
            self.overview_table.update()
            
            # 更新统计
            self.update_statistics()
            
            # 自动调整列宽
            self.overview_table.resizeColumnsToContents()
            
            # 启用导出按钮
            self.export_button.setEnabled(True)
            
            # 切换到概览与统计选项卡
            self.result_tabs.setCurrentIndex(0)
            
            # 如果是恶意IP，高亮显示
            if is_malicious:
                self.highlight_row(row)
                
            print(f"添加IP: {ip} 处理完成\n")
            
        except Exception as e:
            print(f"Error processing IP {ip}: {str(e)}")
            import traceback
            traceback.print_exc()
            self.show_error(f"IP {ip} 处理异常: {str(e)}")
    
    def highlight_row(self, row):
        """高亮显示整行"""
        for column in range(self.overview_table.columnCount()):
            item = self.overview_table.item(row, column)
            if item:
                item.setBackground(QColor(255, 200, 200))  # 淡红色背景
    
    def update_progress(self, current, total):
        """更新进度条"""
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        
        # 更新进度标签
        percent = int(current / total * 100) if total > 0 else 0
        self.progress_label.setText(f"查询进度: {current}/{total} ({percent}%)")
    
    def query_finished(self):
        """查询结束后的处理"""
        self.query_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # 不再隐藏进度条
        # self.progress_bar.setVisible(False)
        
        if self.api_thread and not self.api_thread.stop_flag:
            self.status_bar.showMessage("查询完成")
        else:
            self.status_bar.showMessage("查询已停止")
    
    def show_limit_warning(self, message):
        """显示API限制警告"""
        self.status_bar.showMessage(message)
        # 可选：在界面上显示更显眼的提示
        QMessageBox.warning(self, "API限制", message)
    
    def update_statistics(self):
        """更新统计信息"""
        ips_data = self.current_results.get("data", {})
        total_ips = len(ips_data)
        malicious_ips = 0
        confidence_high = 0
        confidence_medium = 0
        confidence_low = 0
        
        # 地理位置统计
        anhui_count = 0
        china_other_count = 0
        foreign_count = 0
        
        # 运营商统计 - 使用字典存储不同运营商的计数
        carrier_counts = {}
        
        # 判定类型统计 - 使用字典存储不同判定类型的计数
        judgment_counts = {}
        
        # 清除动态创建的标签
        self.clear_dynamic_labels()
        
        # 直接从表格中获取数据进行统计
        for row in range(self.overview_table.rowCount()):
            # 统计恶意IP数量
            is_malicious_item = self.overview_table.item(row, 1)
            if is_malicious_item and is_malicious_item.text() == "是":
                malicious_ips += 1
            
            # 统计可信度分布
            confidence_item = self.overview_table.item(row, 2)
            if confidence_item:
                confidence_text = confidence_item.text()
                # 尝试从保存的原始数据获取英文的confidence值
                confidence = confidence_item.data(Qt.UserRole)
                # 如果没有保存原始数据，则从显示文本反向映射
                if not confidence:
                    reverse_map = {"低": "low", "中": "medium", "高": "high"}
                    confidence = reverse_map.get(confidence_text, confidence_text)
                
                # 对可信度进行计数
                if confidence == "high":
                    confidence_high += 1
                elif confidence == "medium":
                    confidence_medium += 1
                elif confidence == "low":
                    confidence_low += 1
                else:
                    # 尝试从显示文本直接判断
                    if confidence_text == "高":
                        confidence_high += 1
                    elif confidence_text == "中":
                        confidence_medium += 1
                    elif confidence_text == "低":
                        confidence_low += 1
                
                # 输出调试信息
                print(f"Row {row} confidence: {confidence}, Text: {confidence_text}")
            
            # 统计地理位置分布
            location_item = self.overview_table.item(row, 4)
            if location_item:
                location_text = location_item.text()
                if "中国" in location_text or "China" in location_text:
                    if "安徽" in location_text or "Anhui" in location_text:
                        anhui_count += 1
                    else:
                        china_other_count += 1
                elif location_text:
                    foreign_count += 1
            
            # 统计运营商
            carrier_item = self.overview_table.item(row, 5)
            if carrier_item:
                carrier = carrier_item.text()
                if carrier:
                    if carrier in carrier_counts:
                        carrier_counts[carrier] += 1
                    else:
                        carrier_counts[carrier] = 1
            
            # 统计判定类型
            judgment_item = self.overview_table.item(row, 6)
            if judgment_item:
                judgments_text = judgment_item.text()
                if judgments_text:
                    judgment_list = [j.strip() for j in judgments_text.split(",")]
                    for judgment in judgment_list:
                        if judgment:
                            if judgment in judgment_counts:
                                judgment_counts[judgment] += 1
                            else:
                                judgment_counts[judgment] = 1
        
        # 更新基本统计标签
        self.total_ips_label.setText(f"总IP数: {total_ips}")
        
        # 如果有恶意IP，显示警告颜色
        if malicious_ips > 0:
            self.malicious_ips_label.setStyleSheet("font-size: 14px; color: red; font-weight: bold; text-decoration: underline;")
        else:
            self.malicious_ips_label.setStyleSheet("font-size: 14px; color: red; text-decoration: underline;")
        self.malicious_ips_label.setText(f"恶意IP数: {malicious_ips}")
        
        self.safe_ips_label.setText(f"安全IP数: {total_ips - malicious_ips}")
        self.safe_ips_label.setStyleSheet("font-size: 14px; color: green; text-decoration: underline;")
        
        # 更新可信度标签
        self.confidence_high_label.setText(f"高({confidence_high})")
        self.confidence_medium_label.setText(f"中({confidence_medium})")
        self.confidence_low_label.setText(f"低({confidence_low})")
        
        # 更新地理位置标签
        self.anhui_ips_label.setText(f"安徽({anhui_count})")
        self.china_other_ips_label.setText(f"中国其他({china_other_count})")
        self.foreign_ips_label.setText(f"国外({foreign_count})")
        
        # 创建和更新运营商标签
        self.create_dynamic_labels(carrier_counts, self.carrier_labels, self.carrier_labels_layout, "carrier")
        
        # 创建和更新判定类型标签
        self.create_dynamic_labels(judgment_counts, self.judgment_labels, self.judgment_labels_layout, "judgment")
    
    def create_dynamic_labels(self, counts_dict, labels_dict, layout, category_type):
        """创建动态标签"""
        # 按计数从大到小排序，最多显示5个
        sorted_items = sorted(counts_dict.items(), key=lambda x: x[1], reverse=True)
        top_items = sorted_items[:5]
        
        # 颜色列表
        colors = ["#3498db", "#2ecc71", "#e74c3c", "#f39c12", "#9b59b6"]
        
        # 清除布局中所有现有项
        self.clear_layout(layout)
        
        # 创建水平布局，强制靠左对齐
        layout.setAlignment(Qt.AlignLeft)
        
        # 创建新标签并直接添加到布局中
        for i, (name, count) in enumerate(top_items):
            color = colors[i % len(colors)]
            label_text = f"{name}({count})"
            
            label = QLabel(label_text)
            label.setStyleSheet(f"font-size: 14px; color: {color}; text-decoration: underline;")
            label.setCursor(Qt.PointingHandCursor)
            label.setContentsMargins(0, 0, 10, 0)  # 右侧添加10像素边距
            
            # 使用闭包来保存当前循环的值
            def create_click_handler(cat_type, value):
                return lambda event: self.filter_by_category(cat_type, value)
            
            label.mouseReleaseEvent = create_click_handler(category_type, name)
            
            labels_dict[name] = label
            layout.addWidget(label)
    
    def clear_layout(self, layout):
        """清除布局中的所有项"""
        if layout is not None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
    
    def clear_dynamic_labels(self):
        """清除动态创建的标签"""
        # 清除运营商标签
        for label in self.carrier_labels.values():
            self.carrier_labels_layout.removeWidget(label)
            label.deleteLater()
        self.carrier_labels.clear()
        
        # 清除判定类型标签
        for label in self.judgment_labels.values():
            self.judgment_labels_layout.removeWidget(label)
            label.deleteLater()
        self.judgment_labels.clear()
    
    def filter_by_category(self, category, value):
        """根据类别和值过滤表格"""
        print(f"过滤条件: {category}={value}")  # 调试输出
        
        # 取消勾选"仅显示恶意IP"复选框
        self.show_malicious_only.setChecked(False)
        
        # 首先显示所有行
        for row in range(self.overview_table.rowCount()):
            self.overview_table.setRowHidden(row, False)
        
        # 然后根据过滤条件隐藏不满足条件的行
        for row in range(self.overview_table.rowCount()):
            show_row = False
            
            if category == "is_malicious":
                # 过滤恶意/安全IP
                is_malicious_item = self.overview_table.item(row, 1)
                if is_malicious_item:
                    is_malicious = (is_malicious_item.text() == "是")
                    show_row = (is_malicious == value)
            
            elif category == "confidence":
                # 过滤可信度
                confidence_item = self.overview_table.item(row, 2)
                if confidence_item:
                    confidence_text = confidence_item.text()
                    print(f"行 {row} 可信度文本: {confidence_text}")  # 调试输出
                    
                    # 对应关系：高->high, 中->medium, 低->low
                    if value == "high" and confidence_text == "高":
                        show_row = True
                    elif value == "medium" and confidence_text == "中":
                        show_row = True
                    elif value == "low" and confidence_text == "低":
                        show_row = True
                    else:
                        # 尝试从保存的数据中获取
                        confidence_data = confidence_item.data(Qt.UserRole)
                        if confidence_data == value:
                            show_row = True
            
            elif category == "location":
                # 过滤地理位置
                location_item = self.overview_table.item(row, 4)
                if location_item:
                    location_text = location_item.text()
                    
                    if value == "anhui":
                        show_row = ("中国" in location_text or "China" in location_text) and ("安徽" in location_text or "Anhui" in location_text)
                    elif value == "china_other":
                        show_row = ("中国" in location_text or "China" in location_text) and not ("安徽" in location_text or "Anhui" in location_text)
                    elif value == "foreign":
                        show_row = location_text and not ("中国" in location_text or "China" in location_text)
            
            elif category == "carrier":
                # 过滤运营商
                carrier_item = self.overview_table.item(row, 5)
                if carrier_item:
                    carrier = carrier_item.text()
                    show_row = (carrier == value)
            
            elif category == "judgment":
                # 过滤判定类型
                judgment_item = self.overview_table.item(row, 6)
                if judgment_item:
                    judgments_text = judgment_item.text()
                    judgments = [j.strip() for j in judgments_text.split(",")] if judgments_text else []
                    show_row = value in judgments
            
            self.overview_table.setRowHidden(row, not show_row)
        
        # 更新状态栏信息
        visible_rows = sum(1 for row in range(self.overview_table.rowCount()) 
                          if not self.overview_table.isRowHidden(row))
        self.status_bar.showMessage(f"已过滤显示 {visible_rows} 个IP")
    
    def reset_filter(self):
        """重置所有过滤条件"""
        # 显示所有行
        for row in range(self.overview_table.rowCount()):
            self.overview_table.setRowHidden(row, False)
        
        # 应用"仅显示恶意IP"过滤
        if self.show_malicious_only.isChecked():
            self.filter_table()
        
        self.status_bar.showMessage(f"已重置过滤条件，显示 {self.overview_table.rowCount() - sum(1 for row in range(self.overview_table.rowCount()) if self.overview_table.isRowHidden(row))} 个IP")
    
    def show_ip_details(self, row, column):
        # 获取所选IP
        ip = self.overview_table.item(row, 0).text()
        
        if ip in self.current_results.get("data", {}):
            ip_data = self.current_results["data"][ip]
            
            # 生成详细信息
            details = f"<h2>IP: {ip} 详细信息</h2>"
            
            # 基本信息
            details += "<div style='background-color: #f9f9f9; padding: 10px; border-radius: 5px; margin-bottom: 15px;'>"
            details += "<h3 style='color: #2c3e50;'>基本信息</h3>"
            basic = ip_data.get("basic", {})
            location = basic.get("location", {})
            
            details += f"<p><b>运营商:</b> {basic.get('carrier', '未知')}</p>"
            details += f"<p><b>国家/地区:</b> {location.get('country', '未知')} ({location.get('country_code', '')})</p>"
            details += f"<p><b>省份/城市:</b> {location.get('province', '')} {location.get('city', '')}</p>"
            details += f"<p><b>经纬度:</b> {location.get('lat', '')}，{location.get('lng', '')}</p>"
            details += "</div>"
            
            # ASN信息
            if "asn" in ip_data:
                details += "<div style='background-color: #effaf5; padding: 10px; border-radius: 5px; margin-bottom: 15px;'>"
                details += "<h3 style='color: #2c3e50;'>ASN信息</h3>"
                asn = ip_data["asn"]
                details += f"<p><b>ASN号码:</b> {asn.get('number', '')}</p>"
                details += f"<p><b>ASN名称:</b> {asn.get('info', '')}</p>"
                details += f"<p><b>风险值:</b> {asn.get('rank', '')} (0-4, 值越大风险越高)</p>"
                details += "</div>"
            
            # 威胁信息
            is_malicious = ip_data.get("is_malicious", False)
            bg_color = "#fff2f0" if is_malicious else "#f0fff4"
            details += f"<div style='background-color: {bg_color}; padding: 10px; border-radius: 5px; margin-bottom: 15px;'>"
            details += "<h3 style='color: #2c3e50;'>威胁信息</h3>"
            details += f"<p><b>是否恶意:</b> <span style='color: {'red' if is_malicious else 'green'};'>{'是' if is_malicious else '否'}</span></p>"
            
            # 可信度
            confidence = ip_data.get("confidence_level", "")
            confidence_color = {
                "high": "#e74c3c", 
                "medium": "#f39c12", 
                "low": "#3498db"
            }.get(confidence, "black")
            confidence_map = {"low": "低", "medium": "中", "high": "高"}
            confidence_text = confidence_map.get(confidence, confidence)
            details += f"<p><b>可信度:</b> <span style='color: {confidence_color};'>{confidence_text}</span></p>"
            
            # 严重程度
            severity = ip_data.get("severity", "")
            severity_color = {
                "critical": "#c0392b", 
                "high": "#e74c3c", 
                "medium": "#f39c12", 
                "low": "#3498db", 
                "info": "#2ecc71"
            }.get(severity, "black")
            severity_map = {"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "无危胁"}
            severity_text = severity_map.get(severity, severity)
            details += f"<p><b>严重级别:</b> <span style='color: {severity_color};'>{severity_text}</span></p>"
            details += "</div>"
            
            # 判定类型
            if "judgments" in ip_data and ip_data["judgments"]:
                details += "<div style='background-color: #f0f8ff; padding: 10px; border-radius: 5px; margin-bottom: 15px;'>"
                details += "<h3 style='color: #2c3e50;'>判定威胁类型</h3>"
                details += "<ul>"
                for judgment in ip_data["judgments"]:
                    details += f"<li>{judgment}</li>"
                details += "</ul>"
                details += "</div>"
            
            # 标签类别
            if "tags_classes" in ip_data and ip_data["tags_classes"]:
                details += "<div style='background-color: #fff7f0; padding: 10px; border-radius: 5px; margin-bottom: 15px;'>"
                details += "<h3 style='color: #2c3e50;'>相关攻击团伙或安全事件</h3>"
                details += "<ul>"
                for tag in ip_data["tags_classes"]:
                    details += f"<li><b>{tag.get('tags_type', '')}:</b> {', '.join(tag.get('tags', []))}</li>"
                details += "</ul>"
                details += "</div>"
            
            # 历史行为
            if "hist_behavior" in ip_data and ip_data["hist_behavior"]:
                details += "<div style='background-color: #f5f0fa; padding: 10px; border-radius: 5px; margin-bottom: 15px;'>"
                details += "<h3 style='color: #2c3e50;'>攻击行为</h3>"
                details += "<ul>"
                for behavior in ip_data["hist_behavior"]:
                    details += f"<li><b>{behavior.get('category', '')}:</b> {behavior.get('tag_name', '')}"
                    if behavior.get('tag_desc'):
                        details += f" - {behavior.get('tag_desc')}"
                    details += "</li>"
                details += "</ul>"
                details += "</div>"
            
            # 更新时间和应用场景
            details += "<div style='background-color: #f0f0f0; padding: 10px; border-radius: 5px; margin-bottom: 15px;'>"
            # 更新时间
            if "update_time" in ip_data:
                details += f"<p><b>情报更新时间:</b> {ip_data.get('update_time', '')}</p>"
            
            # 应用场景
            if "scene" in ip_data:
                details += f"<p><b>应用场景:</b> {ip_data.get('scene', '')}</p>"
            details += "</div>"
            
            # 影响评估
            if "evaluation" in ip_data:
                details += "<div style='background-color: #f0f4fa; padding: 10px; border-radius: 5px;'>"
                details += "<h3 style='color: #2c3e50;'>影响评估</h3>"
                eval_data = ip_data["evaluation"]
                details += f"<p><b>活跃度:</b> {eval_data.get('active', '')}</p>"
                details += f"<p><b>蜜罐是否捕获:</b> {'是' if eval_data.get('honeypot_hit', False) else '否'}</p>"
                details += "</div>"
            
            # 显示详情
            self.details_text.setHtml(details)
            self.result_tabs.setCurrentIndex(1)  # 切换到详情选项卡
    
    def show_error(self, error_msg):
        self.status_bar.showMessage(f"错误: {error_msg}")
    
    def clear_results(self):
        # 清空输入
        self.ip_input.clear()
        self.ip_count_label.setText("IP数量: 0")
        
        # 清空结果
        self.overview_table.setRowCount(0)
        self.details_text.clear()
        self.json_text.clear()
        
        # 清空统计
        self.total_ips_label.setText("总IP数: 0")
        self.malicious_ips_label.setText("恶意IP数: 0")
        self.safe_ips_label.setText("安全IP数: 0")
        
        # 清空可信度标签
        self.confidence_high_label.setText("高(0)")
        self.confidence_medium_label.setText("中(0)")
        self.confidence_low_label.setText("低(0)")
        
        # 清空地理位置标签
        self.anhui_ips_label.setText("安徽(0)")
        self.china_other_ips_label.setText("中国其他(0)")
        self.foreign_ips_label.setText("国外(0)")
        
        # 清空动态创建的标签
        self.clear_dynamic_labels()
        
        # 清空存储的结果
        self.current_results = {"data": {}}
        
        # 禁用导出按钮
        self.export_button.setEnabled(False)
        
        # 更新状态栏
        self.status_bar.showMessage("已清除")
    
    def export_results(self):
        """导出查询结果"""
        if not self.current_results or not self.current_results.get("data"):
            QMessageBox.warning(self, "警告", "没有可导出的数据")
            return
        
        # 获取保存文件路径
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出结果", "", "CSV文件 (*.csv);;JSON文件 (*.json);;全部文件 (*)"
        )
        
        if not file_path:
            return
        
        try:
            # 根据文件扩展名选择导出格式
            if file_path.endswith('.csv'):
                # 询问编码方式
                encoding, ok = self.get_encoding_choice()
                if not ok:
                    return
                self.export_as_csv(file_path, encoding)
            elif file_path.endswith('.json'):
                self.export_as_json(file_path)
            else:
                # 默认为CSV
                if not file_path.endswith('.csv'):
                    file_path += '.csv'
                encoding, ok = self.get_encoding_choice()
                if not ok:
                    return
                self.export_as_csv(file_path, encoding)
                
            QMessageBox.information(self, "成功", f"结果已成功导出到: {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
    
    def get_encoding_choice(self):
        """获取用户选择的编码方式"""
        items = ["UTF-8 (通用)", "GB18030 (中文Windows)", "GBK (中文系统)", "GB2312 (简体中文)"]
        encoding, ok = QInputDialog.getItem(self, "选择编码方式", "请选择CSV文件编码:", items, 0, False)
        
        if not ok:
            return None, False
        
        # 映射用户选择到实际编码
        encoding_map = {
            "UTF-8 (通用)": "utf-8-sig",  # 使用带BOM的UTF-8
            "GB18030 (中文Windows)": "gb18030",
            "GBK (中文系统)": "gbk",
            "GB2312 (简体中文)": "gb2312"
        }
        
        return encoding_map.get(encoding, "utf-8-sig"), True
    
    def export_as_csv(self, file_path, encoding="utf-8-sig"):
        """将结果导出为CSV文件"""
        with open(file_path, 'w', newline='', encoding=encoding) as csvfile:
            fieldnames = ['IP地址', '是否恶意', '可信度', '严重程度', '国家', '省份', '城市', '运营商', '判定类型', 'ASN号码', 'ASN名称', '更新时间']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for ip, data in self.current_results.get("data", {}).items():
                basic = data.get("basic", {})
                location = basic.get("location", {})
                asn = data.get("asn", {})
                
                confidence_map = {"low": "低", "medium": "中", "high": "高"}
                severity_map = {"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "无危胁"}
                
                row = {
                    'IP地址': ip,
                    '是否恶意': "是" if data.get("is_malicious", False) else "否",
                    '可信度': confidence_map.get(data.get("confidence_level", ""), data.get("confidence_level", "")),
                    '严重程度': severity_map.get(data.get("severity", ""), data.get("severity", "")),
                    '国家': location.get("country", ""),
                    '省份': location.get("province", ""),
                    '城市': location.get("city", ""),
                    '运营商': basic.get("carrier", ""),
                    '判定类型': ", ".join(data.get("judgments", [])),
                    'ASN号码': asn.get("number", ""),
                    'ASN名称': asn.get("info", ""),
                    '更新时间': data.get("update_time", "")
                }
                writer.writerow(row)
    
    def export_as_json(self, file_path):
        """将结果导出为JSON文件"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump({"data": self.current_results["data"]}, f, indent=4, ensure_ascii=False)
    
    def load_api_key(self):
        """从设置加载API密钥"""
        api_key = self.settings.value("api_key", "")
        if api_key:
            self.api_key_input.setText(api_key)

    def import_file(self):
        """从文件导入IP地址"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择文件", "", "文本文件 (*.txt);;CSV文件 (*.csv);;所有文件 (*)"
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # 如果当前输入框有内容，添加换行符
            current_text = self.ip_input.toPlainText().strip()
            if current_text:
                self.ip_input.setText(current_text + "\n" + content)
            else:
                self.ip_input.setText(content)
                
            self.status_bar.showMessage(f"已从文件导入内容: {file_path}")
            
            # 处理导入的IP
            self.process_ips()
            
        except Exception as e:
            QMessageBox.critical(self, "导入错误", f"导入文件时出错: {str(e)}")
            self.status_bar.showMessage("导入文件失败")

    def copy_json(self):
        """复制JSON到剪贴板"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.json_text.toPlainText())
        self.status_bar.showMessage("JSON已复制到剪贴板")
    
    def copy_selected_ip(self):
        """复制选中的IP到剪贴板"""
        selected_items = self.overview_table.selectedItems()
        if not selected_items:
            self.status_bar.showMessage("请先选择IP")
            return
        
        # 获取选中的行号
        selected_rows = set()
        for item in selected_items:
            selected_rows.add(item.row())
        
        # 获取选中行的IP地址
        selected_ips = []
        for row in selected_rows:
            ip_item = self.overview_table.item(row, 0)
            if ip_item:
                selected_ips.append(ip_item.text())
        
        if selected_ips:
            clipboard = QApplication.clipboard()
            clipboard.setText("\n".join(selected_ips))
            self.status_bar.showMessage(f"已复制 {len(selected_ips)} 个IP到剪贴板")
    
    def filter_table(self):
        """根据复选框状态过滤表格，只显示恶意IP"""
        show_only_malicious = self.show_malicious_only.isChecked()
        
        # 先检查每行目前的可见状态，避免与其他过滤条件冲突
        for row in range(self.overview_table.rowCount()):
            # 如果行已经被其他条件隐藏，则保持隐藏状态
            if not self.overview_table.isRowHidden(row):
                is_malicious_item = self.overview_table.item(row, 1)
                if is_malicious_item:
                    is_malicious = (is_malicious_item.text() == "是")
                    # 如果要显示恶意IP但当前IP不是恶意的，则隐藏
                    if show_only_malicious and not is_malicious:
                        self.overview_table.setRowHidden(row, True)
        
        # 如果取消勾选，则需要显示所有符合其他过滤条件的行
        if not show_only_malicious:
            # 我们需要重新应用所有当前生效的过滤条件
            # 这个操作复杂，需要保存当前过滤状态，所以简单做法是重置所有过滤
            self.reset_filter()
        
        # 更新状态栏信息
        visible_rows = sum(1 for row in range(self.overview_table.rowCount()) 
                          if not self.overview_table.isRowHidden(row))
        self.status_bar.showMessage(f"显示 {visible_rows} 个IP")
    
    def sort_table(self):
        """根据选择的列和方向对表格进行排序"""
        column = self.sort_combo.currentIndex()
        direction = Qt.AscendingOrder if self.sort_direction.currentIndex() == 0 else Qt.DescendingOrder
        self.overview_table.sortItems(column, direction)
    
    def export_current_view(self):
        """导出当前视图中的数据"""
        # 获取保存文件路径
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出当前视图", "", "CSV文件 (*.csv);;全部文件 (*)"
        )
        
        if not file_path:
            return
        
        try:
            # 如果没有.csv后缀，添加
            if not file_path.endswith('.csv'):
                file_path += '.csv'
            
            # 询问编码方式
            encoding, ok = self.get_encoding_choice()
            if not ok:
                return
            
            with open(file_path, 'w', newline='', encoding=encoding) as csvfile:
                # 获取表头
                header = []
                for col in range(self.overview_table.columnCount()):
                    header.append(self.overview_table.horizontalHeaderItem(col).text())
                
                writer = csv.writer(csvfile)
                writer.writerow(header)
                
                # 获取可见行
                for row in range(self.overview_table.rowCount()):
                    if not self.overview_table.isRowHidden(row):
                        row_data = []
                        for col in range(self.overview_table.columnCount()):
                            item = self.overview_table.item(row, col)
                            if item:
                                row_data.append(item.text())
                            else:
                                row_data.append("")
                        writer.writerow(row_data)
            
            QMessageBox.information(self, "成功", f"当前视图已成功导出到: {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
            
    def stop_query(self):
        """停止当前查询"""
        if self.api_thread and self.api_thread.isRunning():
            self.api_thread.stop()
            self.status_bar.showMessage("正在停止查询...")
            
    def highlight_malicious_ips(self):
        """高亮显示恶意IP"""
        for row in range(self.overview_table.rowCount()):
            is_malicious_item = self.overview_table.item(row, 1)
            if is_malicious_item and is_malicious_item.text() == "是":
                self.highlight_row(row)

    def create_single_result_object(self, ip, data):
        """创建单个IP的API响应结果对象"""
        # 创建与API响应格式相同的结果对象
        return {
            "response_code": 0,
            "verbose_msg": "Ok",
            "data": {
                ip: data
            }
        }

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # 设置应用样式
    app.setStyle("Fusion")
    
    window = IPReputationApp()
    window.show()
    sys.exit(app.exec_()) 