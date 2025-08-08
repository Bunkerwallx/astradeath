#!/usr/bin/env python3
"""
AstraDeath - Herramienta forense avanzada para análisis de imágenes de disco y memoria (Nivel NSA/FBI)
Desarrollado por: Cristo Leon
Versión: 4.3 | Código: CVLP-2025
Licencia: Particular
"""

import pytsk3
import argparse
import asyncio
import aiofiles
from datetime import datetime
import hashlib
import csv
import json
import os
import sys
from tqdm import tqdm
import libewf
import magic
import pytz
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import xml.etree.ElementTree as ET
import logging
from colorama import init, Fore, Style
import zipfile
from cryptography.fernet import Fernet
import aiosqlite
from aiohttp import web
import socketio
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.completion import WordCompleter
import subprocess
import pkg_resources
import locale
import exiftool
import olefile
import PyPDF2
from PIL import Image
import io
import math
import numpy as np
import volatility3
from volatility3.framework import automagic, contexts, interfaces
from volatility3.framework.plugins import construct_plugin
from volatility3.plugins.windows import pslist, netscan, malfind

# Base de datos de extensiones conocidas
KNOWN_EXTENSIONS = {
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.pdf': 'application/pdf',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.jpg': 'image/jpeg',
    '.png': 'image/png',
    '.txt': 'text/plain',
    '.log': 'text/plain',
    '.db': 'application/x-sqlite3',
    '.config': 'text/plain',
    '.exe': 'application/x-msdownload',
    '.zip': 'application/zip',
    '.mp4': 'video/mp4',
    '.mp3': 'audio/mpeg',
}

class AstraDeathAnalyzer:
    def __init__(self, image_paths, memory_image=None, log_file="astradeath.log", language="es"):
        """
        Inicializa el analizador forense.

        Args:
            image_paths (list): Rutas a las imágenes forenses.
            memory_image (str): Ruta a la imagen de memoria (opcional).
            log_file (str): Archivo de registro para auditoría.
            language (str): Idioma ('es' o 'en').
        """
        init()  # Inicializar colorama
        self.image_paths = image_paths if isinstance(image_paths, list) else [image_paths]
        self.memory_image = memory_image
        self.log_file = log_file
        self.language = language
        locale.setlocale(locale.LC_ALL, 'es_ES.UTF-8' if language == 'es' else 'en_US.UTF-8')
        self._setup_logging()
        self.magic = magic.Magic(mime=True)
        self.mime_cache = {}
        self.timezone = pytz.timezone('UTC')
        self.images = [self._initialize_image_handler(path) for path in self.image_paths]
        self.partitions = [self._detect_partitions(img) for img in self.images]
        self.filesystem = None
        self.file_count = 0
        self.found_items = []
        self.extension_stats = defaultdict(int)
        self.stats = defaultdict(int)
        self.memory_results = {'processes': [], 'connections': [], 'injections': []}
        self.total_entries = 0
        self.progress_bar = None
        self.hash_cache = {}
        self.sio = socketio.AsyncServer()
        self.app = web.Application()
        self.sio.attach(self.app)
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.messages = {
            'es': {
                'initializing': "[*] Inicializando AstraDeath...",
                'starting': "[*] Comenzando análisis forense...",
                'parameters': "[*] Parámetros de escaneo:",
                'no_matches': "[!] No se encontraron archivos que coincidan con los criterios",
                'report_generated': "[✓] Reporte generado: {} ({})",
                'report_error': "[✖] Error generando reporte: {}",
                'analysis_completed': "[✓] Análisis completado con éxito",
                'interrupted': "[!] Análisis interrumpido por el usuario",
                'fatal_error': "[✖] Error fatal: {}",
                'installing_deps': "[*] Instalando dependencias...",
                'deps_installed': "[✓] Dependencias instaladas correctamente",
                'deps_error': "[✖] Error instalando dependencias: {}",
                'extensions_found': "[*] Extensiones encontradas: {}",
                'steg_detected': "[!] Posible esteganografía detectada en: {}",
                'slack_space': "[*] Datos recuperados de slack space: {} bytes",
                'memory_analysis': "[*] Analizando imagen de memoria: {}",
                'malicious_injection': "[!] Inyección de código detectada en proceso: {} (PID: {})"
            },
            'en': {
                'initializing': "[*] Initializing AstraDeath...",
                'starting': "[*] Starting forensic analysis...",
                'parameters': "[*] Scan parameters:",
                'no_matches': "[!] No files found matching the criteria",
                'report_generated': "[✓] Report generated: {} ({})",
                'report_error': "[✖] Error generating report: {}",
                'analysis_completed': "[✓] Analysis completed successfully",
                'interrupted': "[!] Analysis interrupted by user",
                'fatal_error': "[✖] Fatal error: {}",
                'installing_deps': "[*] Installing dependencies...",
                'deps_installed': "[✓] Dependencies installed successfully",
                'deps_error': "[✖] Error installing dependencies: {}",
                'extensions_found': "[*] Extensions found: {}",
                'steg_detected': "[!] Possible steganography detected in: {}",
                'slack_space': "[*] Data recovered from slack space: {} bytes",
                'memory_analysis': "[*] Analyzing memory image: {}",
                'malicious_injection': "[!] Code injection detected in process: {} (PID: {})"
            }
        }

    def _setup_logging(self):
        """Configura el sistema de registro."""
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        logging.info(f"Iniciando análisis de imágenes: {', '.join(self.image_paths)}")
        if self.memory_image:
            logging.info(f"Iniciando análisis de memoria: {self.memory_image}")

    def _install_dependencies(self):
        """Instala dependencias automáticamente."""
        required = {'pytsk3', 'python-magic', 'tqdm', 'libewf-python', 'colorama',
                    'aiofiles', 'aiosqlite', 'aiohttp', 'python-socketio', 'cryptography',
                    'prompt_toolkit', 'jinja2', 'pyexiftool', 'olefile', 'PyPDF2', 'Pillow', 'numpy',
                    'volatility3'}
        installed = {pkg.key for pkg in pkg_resources.working_set}
        missing = required - installed

        if missing:
            print(f"{Fore.CYAN}{self.messages[self.language]['installing_deps']}{Style.RESET_ALL}")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', *missing])
                print(f"{Fore.GREEN}{self.messages[self.language]['deps_installed']}{Style.RESET_ALL}")
            except subprocess.CalledProcessError as e:
                print(f"{Fore.RED}{self.messages[self.language]['deps_error'].format(str(e))}{Style.RESET_ALL}")
                sys.exit(1)

    def _initialize_image_handler(self, image_path):
        """
        Inicializa el manejador de imagen con soporte para E01.

        Args:
            image_path (str): Ruta a la imagen.

        Returns:
            pytsk3.Img_Info: Objeto de imagen.
        """
        try:
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"La imagen {image_path} no existe")
            if image_path.lower().endswith(('.e01', '.ewf')):
                handle = libewf.libewf_handle_initialize()
                libewf.libewf_handle_open(handle, [image_path], libewf.LIBEWF_OPEN_READ)
                return pytsk3.Img_Info(handle)
            return pytsk3.Img_Info(image_path)
        except Exception as e:
            logging.error(f"Error al abrir la imagen {image_path}: {e}")
            print(f"{Fore.RED}{self.messages[self.language]['fatal_error'].format(str(e))}{Style.RESET_ALL}")
            sys.exit(1)

    def _detect_partitions(self, image):
        """
        Detecta particiones en la imagen.

        Args:
            image: Objeto de imagen pytsk3.

        Returns:
            list: Lista de particiones válidas.
        """
        try:
            volume = pytsk3.Volume_Info(image)
            return [part for part in volume if part.len > 0 and
                    part.desc.decode().lower().startswith(('ntfs', 'fat', 'ext', 'hfs', 'apfs'))]
        except Exception:
            return [{'start': 0, 'len': -1}]

    def _initialize_filesystem(self, partition, image):
        """
        Inicializa el sistema de archivos para una partición.

        Args:
            partition (dict): Información de la partición.
            image: Objeto de imagen pytsk3.

        Returns:
            pytsk3.FS_Info: Objeto del sistema de archivos.
        """
        try:
            offset = partition['start'] * 512
            return pytsk3.FS_Info(image, offset=offset)
        except Exception as e:
            logging.error(f"Error al acceder al sistema de archivos en partición {partition['start']}: {e}")
            return None

    async def _calculate_forensic_hashes(self, file_obj, size, inode):
        """
        Calcula hashes forenses con caché.

        Args:
            file_obj: Objeto de archivo pytsk3.
            size (int): Tamaño del archivo.
            inode (int): Identificador único del archivo.

        Returns:
            dict: Hashes calculados o valores de error.
        """
        if inode in self.hash_cache:
            return self.hash_cache[inode]

        algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        try:
            block_size = 1024 * 1024
            async with aiofiles.tempfile.NamedTemporaryFile() as tmp:
                for offset in range(0, size, block_size):
                    data = file_obj.read_random(offset, min(block_size, size - offset))
                    if not data:
                        break
                    await tmp.write(data)
                    for algo in algorithms.values():
                        algo.update(data)
                hashes = {name: algo.hexdigest() for name, algo in algorithms.items()}
                self.hash_cache[inode] = hashes
                return hashes
        except Exception as e:
            logging.warning(f"Error en cálculo de hashes: {e}")
            return {name: "ERROR" for name in algorithms.keys()}

    async def _calculate_entropy(self, data):
        """
        Calcula la entropía de un archivo para el ADN digital.

        Args:
            data (bytes): Datos del archivo.

        Returns:
            float: Entropía del archivo.
        """
        if not data:
            return 0.0
        length = len(data)
        if length == 0:
            return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
        probs = counts / length
        probs = probs[probs > 0]
        return -np.sum(probs * np.log2(probs))

    async def _extract_hidden_metadata(self, file_obj, size, filename, mime_type):
        """
        Extrae metadatos ocultos de archivos (EXIF, Office, PDF).

        Args:
            file_obj: Objeto de archivo pytsk3.
            size (int): Tamaño del archivo.
            filename (str): Nombre del archivo.
            mime_type (str): Tipo MIME del archivo.

        Returns:
            dict: Metadatos ocultos.
        """
        metadata = {}
        try:
            data = file_obj.read_random(0, min(size, 1024*1024))  # Limitar a 1MB
            if mime_type.startswith('image/'):
                with exiftool.ExifTool() as et:
                    with io.BytesIO(data) as f:
                        metadata = et.get_metadata(f)
            elif mime_type == 'application/pdf':
                with io.BytesIO(data) as f:
                    pdf = PyPDF2.PdfFileReader(f)
                    metadata = pdf.getDocumentInfo()
                    if pdf.getXmpMetadata():
                        metadata['xmp'] = pdf.getXmpMetadata()
            elif mime_type.startswith('application/vnd'):
                with io.BytesIO(data) as f:
                    if olefile.isOleFile(f):
                        ole = olefile.OleFileIO(f)
                        metadata = ole.get_metadata().__dict__
                        ole.close()
        except Exception as e:
            logging.warning(f"Error extrayendo metadatos ocultos de {filename}: {e}")
        return metadata

    async def _carve_slack_space(self, entry, block_size=512):
        """
        Realiza carving en el slack space de un archivo.

        Args:
            entry: Entrada del sistema de archivos.
            block_size (int): Tamaño del bloque del sistema de archivos.

        Returns:
            bytes: Datos recuperados del slack space.
        """
        try:
            size = entry.info.meta.size
            allocated_size = ((size + block_size - 1) // block_size) * block_size
            slack_size = allocated_size - size
            if slack_size <= 0:
                return b""
            file_obj = entry.as_file()
            slack_data = file_obj.read_random(size, slack_size)
            return slack_data
        except Exception as e:
            logging.warning(f"Error en carving de slack space: {e}")
            return b""

    async def _detect_steganography(self, file_obj, size, filename, mime_type):
        """
        Detecta posible esteganografía en imágenes y PDFs.

        Args:
            file_obj: Objeto de archivo pytsk3.
            size (int): Tamaño del archivo.
            filename (str): Nombre del archivo.
            mime_type (str): Tipo MIME del archivo.

        Returns:
            dict: Resultados de la detección.
        """
        results = {'steg_detected': False, 'details': []}
        try:
            if mime_type.startswith('image/'):
                data = file_obj.read_random(0, min(size, 1024*1024))
                with Image.open(io.BytesIO(data)) as img:
                    pixels = np.array(img)
                    lsb = pixels & 1
                    if np.mean(lsb) > 0.5 or np.mean(lsb) < 0.1:
                        results['steg_detected'] = True
                        results['details'].append("LSB anómalo detectado")
                        print(f"{Fore.YELLOW}{self.messages[self.language]['steg_detected'].format(filename)}{Style.RESET_ALL}")
            elif mime_type == 'application/pdf':
                data = file_obj.read_random(0, min(size, 1024*1024))
                if b'/ObjStm' in data or b'/JavaScript' in data:
                    results['steg_detected'] = True
                    results['details'].append("Objetos sospechosos en PDF")
                    print(f"{Fore.YELLOW}{self.messages[self.language]['steg_detected'].format(filename)}{Style.RESET_ALL}")
        except Exception as e:
            logging.warning(f"Error detectando esteganografía en {filename}: {e}")
        return results

    async def _generate_digital_dna(self, file_obj, size, metadata, filename):
        """
        Genera un ADN digital único para el archivo.

        Args:
            file_obj: Objeto de archivo pytsk3.
            size (int): Tamaño del archivo.
            metadata (dict): Metadatos del archivo.
            filename (str): Nombre del archivo.

        Returns:
            dict: ADN digital.
        """
        dna = {}
        try:
            hashes = await self._calculate_forensic_hashes(file_obj, size, metadata['inode'])
            data = file_obj.read_random(0, min(size, 1024*1024))
            entropy = await self._calculate_entropy(data)
            dna = {
                'hashes': hashes,
                'size': size,
                'mtime': metadata.get('mtime', 'N/A'),
                'permissions': metadata.get('attributes', {}).get('permissions', 0),
                'entropy': entropy,
                'filename': filename
            }
            dna['dna_hash'] = hashlib.sha256(json.dumps(dna, sort_keys=True).encode()).hexdigest()
        except Exception as e:
            logging.warning(f"Error generando ADN digital para {filename}: {e}")
        return dna

    async def analyze_memory_dump(self, memory_image):
        """
        Analiza una imagen de memoria usando Volatility 3.

        Args:
            memory_image (str): Ruta a la imagen de memoria.

        Returns:
            dict: Resultados del análisis (procesos, conexiones, inyecciones).
        """
        print(f"{Fore.CYAN}{self.messages[self.language]['memory_analysis'].format(memory_image)}{Style.RESET_ALL}")
        logging.info(f"Analizando imagen de memoria: {memory_image}")

        try:
            # Configurar contexto de Volatility
            ctx = contexts.Context()
            automagics = automagic.available(ctx)
            config_path = interfaces.configuration.path_join("astradeath", "memory_analysis")

            # Plugin: pslist (Listado de procesos)
            plugin = construct_plugin(ctx, automagics, pslist.PsList, config_path, None, memory_image)
            tree_grid = plugin.run()
            for row in tree_grid:
                process = {
                    'pid': row.PID,
                    'name': row.ImageFileName,
                    'ppid': row.PPID,
                    'threads': row.Threads,
                    'handles': row.Handles,
                    'create_time': str(row.CreateTime)
                }
                self.memory_results['processes'].append(process)
                await self.sio.emit('memory_progress', {'type': 'process', 'data': process})

            # Plugin: netscan (Conexiones de red)
            plugin = construct_plugin(ctx, automagics, netscan.NetScan, config_path, None, memory_image)
            tree_grid = plugin.run()
            for row in tree_grid:
                connection = {
                    'protocol': row.Proto,
                    'local_addr': str(row.LocalAddress),
                    'remote_addr': str(row.RemoteAddress),
                    'state': row.State,
                    'pid': row.PID,
                    'owner': row.Owner
                }
                self.memory_results['connections'].append(connection)
                await self.sio.emit('memory_progress', {'type': 'connection', 'data': connection})

            # Plugin: malfind (Detección de inyecciones de código)
            plugin = construct_plugin(ctx, automagics, malfind.MalFind, config_path, None, memory_image)
            tree_grid = plugin.run()
            for row in tree_grid:
                injection = {
                    'pid': row.PID,
                    'process_name': row.ProcessName,
                    'address': hex(row.StartVPN),
                    'size': row.Size,
                    'data': row.Data[:100].hex() if row.Data else "N/A"
                }
                entropy = await self._calculate_entropy(row.Data) if row.Data else 0.0
                injection['entropy'] = entropy
                if entropy > 7.0:  # Umbral para detectar código ofuscado
                    print(f"{Fore.YELLOW}{self.messages[self.language]['malicious_injection'].format(row.ProcessName, row.PID)}{Style.RESET_ALL}")
                    logging.warning(f"Inyección de código detectada: {row.ProcessName} (PID: {row.PID})")
                self.memory_results['injections'].append(injection)
                await self.sio.emit('memory_progress', {'type': 'injection', 'data': injection})

            return self.memory_results
        except Exception as e:
            logging.error(f"Error analizando memoria: {e}")
            print(f"{Fore.RED}{self.messages[self.language]['fatal_error'].format(str(e))}{Style.RESET_ALL}")
            return {}

    async def _analyze_file_content(self, file_obj, size, filename=None):
        """
        Analiza el contenido del archivo y detecta anomalías.

        Args:
            file_obj: Objeto de archivo pytsk3.
            size (int): Tamaño del archivo.
            filename (str): Nombre del archivo.

        Returns:
            dict: Información del contenido.
        """
        try:
            sample = file_obj.read_random(0, min(4096, size))
            mime_type = self.mime_cache.get(filename, self.magic.from_buffer(sample) if sample else 'unknown')
            if filename:
                self.mime_cache[filename] = mime_type
            is_text = b'\x00' not in sample if sample else False
            keywords = []
            anomalies = []
            detected_extension = None

            if not filename or not filename.endswith(tuple(KNOWN_EXTENSIONS.keys())):
                for ext, known_mime in KNOWN_EXTENSIONS.items():
                    if mime_type == known_mime:
                        detected_extension = ext
                        break
            else:
                detected_extension = os.path.splitext(filename)[1].lower()

            if is_text and sample:
                try:
                    text = sample.decode('utf-8', errors='ignore').lower()
                    keywords = [word for word in ['contraseña', 'confidencial', 'secreto']
                              if word in text]
                    if any(c in text for c in ['<?php', 'eval(', 'malware']):
                        anomalies.append("Contenido potencialmente malicioso")
                except:
                    pass

            hidden_metadata = await self._extract_hidden_metadata(file_obj, size, filename, mime_type)
            steg_results = await self._detect_steganography(file_obj, size, filename, mime_type)

            return {
                'mime_type': mime_type,
                'is_text': is_text,
                'size': size,
                'keywords': keywords,
                'anomalies': anomalies,
                'detected_extension': detected_extension,
                'hidden_metadata': hidden_metadata,
                'steganography': steg_results
            }
        except:
            return {
                'mime_type': 'desconocido',
                'is_text': False,
                'size': size,
                'keywords': [],
                'anomalies': [],
                'detected_extension': None,
                'hidden_metadata': {},
                'steganography': {'steg_detected': False, 'details': []}
            }

    async def _process_timestamps(self, metadata):
        """
        Procesa y formatea marcas de tiempo.

        Args:
            metadata: Metadatos del archivo.

        Returns:
            dict: Tiempos formateados.
        """
        def format_time(ts):
            if ts and ts > 0:
                return self.timezone.localize(datetime.fromtimestamp(ts)).isoformat()
            return "N/A"
        
        return {
            'mtime': format_time(metadata.mtime),
            'ctime': format_time(metadata.ctime),
            'atime': format_time(metadata.atime),
            'crtime': format_time(metadata.crtime) if hasattr(metadata, 'crtime') else "N/A"
        }

    async def _extract_file(self, entry, output_dir, filename=None):
        """
        Extrae un archivo a un directorio especificado.

        Args:
            entry: Entrada del sistema de archivos.
            output_dir (str): Directorio de destino.
            filename (str): Nombre del archivo.
        """
        try:
            name = filename or entry.info.name.name.decode('utf-8', errors='replace')
            output_path = os.path.join(output_dir, name)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            async with aiofiles.open(output_path, 'wb') as f:
                file_obj = entry.as_file()
                size = entry.info.meta.size
                for offset in range(0, size, 1024*1024):
                    data = file_obj.read_random(offset, min(1024*1024, size - offset))
                    if not data:
                        break
                    await f.write(data)
            logging.info(f"Archivo extraído: {output_path}")
            print(f"{Fore.GREEN}[✓] Extraído: {output_path}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error extrayendo archivo: {e}")

    async def _recover_deleted_files(self, filesystem, path, extensions, extract_dir=None):
        """
        Recupera archivos eliminados.

        Args:
            filesystem: Objeto del sistema de archivos.
            path (str): Ruta a escanear.
            extensions (list): Extensiones a buscar.
            extract_dir (str): Directorio para extracción.

        Returns:
            list: Archivos recuperados.
        """
        recovered = []
        try:
            for entry in filesystem.open_dir(path=path):
                if not entry.info.meta or not entry.info.name.name:
                    continue
                if entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                    name = entry.info.name.name.decode('utf-8', errors='replace')
                    full_path = os.path.join(path, name).replace("\\", "/")
                    file_obj = entry.as_file()
                    size = entry.info.meta.size
                    content_info = await self._analyze_file_content(file_obj, size, name)
                    if extensions == ['all'] or content_info['detected_extension'] in extensions:
                        file_info = {
                            'path': full_path,
                            'name': name,
                            'inode': entry.info.meta.addr,
                            'type': 'ARCHIVO',
                            'status': 'DELETED',
                            **(await self._process_timestamps(entry.info.meta)),
                            **content_info
                        }
                        if size <= 100 * 1024 * 1024:
                            file_info['hashes'] = await self._calculate_forensic_hashes(file_obj, size, entry.info.meta.addr)
                            file_info['digital_dna'] = await self._generate_digital_dna(file_obj, size, file_info, name)
                        slack_data = await self._carve_slack_space(entry)
                        if slack_data:
                            file_info['slack_space'] = len(slack_data)
                            print(f"{Fore.CYAN}{self.messages[self.language]['slack_space'].format(len(slack_data))}{Style.RESET_ALL}")
                        if extract_dir:
                            await self._extract_file(entry, extract_dir, name)
                        recovered.append(file_info)
                        self.extension_stats[content_info['detected_extension']] += 1
        except Exception as e:
            logging.warning(f"Error recuperando archivos eliminados en {path}: {e}")
        return recovered

    async def scan_filesystem(self, path="/", extensions=None, max_size_mb=100, min_size_mb=0,
                             depth=5, date_filter=None, keyword=None, extract_dir=None,
                             recover_deleted=False, analyze_hidden=False, detect_steg=False):
        """
        Escanea el sistema de archivos recursivamente con filtros avanzados.

        Args:
            path (str): Ruta inicial.
            extensions (list): Extensiones a buscar ('all' para todas las conocidas).
            max_size_mb (int): Tamaño máximo en MB.
            min_size_mb (int): Tamaño mínimo en MB.
            depth (int): Profundidad de directorios.
            date_filter (tuple): Rango de fechas (inicio, fin).
            keyword (str): Palabra clave en el nombre.
            extract_dir (str): Directorio para extracción.
            recover_deleted (bool): Recuperar archivos eliminados.
            analyze_hidden (bool): Analizar metadatos ocultos.
            detect_steg (bool): Detectar esteganografía.
        """
        if extensions is None:
            extensions = ['.docx', '.pdf', '.xlsx', '.db', '.log', '.config']
        elif extensions == ['all']:
            extensions = list(KNOWN_EXTENSIONS.keys())

        for img_idx, image in enumerate(self.images):
            for partition in self.partitions[img_idx]:
                self.filesystem = self._initialize_filesystem(partition, image)
                if not self.filesystem:
                    continue

                try:
                    entries = list(self.filesystem.open_dir(path=path))
                    self.total_entries += len(entries)
                    if not self.progress_bar:
                        self.progress_bar = tqdm(total=self.total_entries, desc="Escaneando sistema de archivos", unit="archivo")

                    if recover_deleted:
                        deleted_files = await self._recover_deleted_files(self.filesystem, path, extensions, extract_dir)
                        self.found_items.extend(deleted_files)
                        self.stats['deleted_files'] += len(deleted_files)

                    tasks = []
                    for entry in entries:
                        tasks.append(self._process_entry(entry, path, extensions, max_size_mb, min_size_mb,
                                                        depth, date_filter, keyword, extract_dir,
                                                        analyze_hidden, detect_steg))
                    for result in await asyncio.gather(*tasks, return_exceptions=True):
                        self.progress_bar.update(1)
                        if isinstance(result, dict):
                            self.found_items.append(result)
                            self.file_count += 1
                            self.extension_stats[result['detected_extension']] += 1
                            logging.info(f"Archivo encontrado: {result['path']}")
                            await self.sio.emit('progress', {'file': result['path'], 'count': self.file_count,
                                                            'extensions': dict(self.extension_stats),
                                                            'steg': result['steganography']['steg_detected']})
                            print(f"{Fore.GREEN}[✓] #{self.file_count} {result['path']} ({result['size']/1024:.1f} KB){Style.RESET_ALL}")

                except Exception as e:
                    logging.error(f"Error accediendo a {path}: {e}")
                    print(f"{Fore.RED}[!] Error accediendo a {path}: {str(e)}{Style.RESET_ALL}")

        if self.memory_image:
            await self.analyze_memory_dump(self.memory_image)

        print(f"{Fore.CYAN}{self.messages[self.language]['extensions_found'].format(dict(self.extension_stats))}{Style.RESET_ALL}")

    async def _process_entry(self, entry, path, extensions, max_size_mb, min_size_mb, depth, date_filter, keyword, extract_dir,
                             analyze_hidden, detect_steg):
        """
        Procesa una entrada del sistema de archivos.

        Args:
            entry: Entrada del sistema de archivos.
            path (str): Ruta actual.
            extensions (list): Extensiones a buscar.
            max_size_mb (int): Tamaño máximo en MB.
            min_size_mb (int): Tamaño mínimo en MB.
            depth (int): Profundidad de directorios.
            date_filter (tuple): Rango de fechas (inicio, fin).
            keyword (str): Palabra clave en el nombre.
            extract_dir (str): Directorio para extracción.
            analyze_hidden (bool): Analizar metadatos ocultos.
            detect_steg (bool): Detectar esteganografía.

        Returns:
            dict: Información del archivo o None.
        """
        try:
            if not entry.info.meta or not entry.info.name.name:
                return None

            name = entry.info.name.name.decode('utf-8', errors='replace')
            full_path = os.path.join(path, name).replace("\\", "/")
            file_info = {
                'path': full_path,
                'name': name,
                'inode': entry.info.meta.addr,
                'type': 'DIRECTORIO' if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR else 'ARCHIVO',
                'attributes': {
                    'permissions': entry.info.meta.mode,
                    'owner': entry.info.meta.uid,
                    'group': entry.info.meta.gid,
                    'flags': entry.info.meta.flags
                },
                **(await self._process_timestamps(entry.info.meta))
            }

            if file_info['type'] == 'DIRECTORIO':
                self.stats['directories'] += 1
                if name not in (".", "..") and depth > 0:
                    await self.scan_filesystem(full_path, extensions, max_size_mb, min_size_mb,
                                             depth-1, date_filter, keyword, extract_dir, analyze_hidden, detect_steg)
                return None

            self.stats['files'] += 1
            file_obj = entry.as_file()
            size = entry.info.meta.size
            content_info = await self._analyze_file_content(file_obj, size, name)
            file_info.update(content_info)

            # Aplicar filtros
            if extensions != ['all'] and not any(name.lower().endswith(ext) for ext in extensions):
                return None
            if size > max_size_mb * 1024 * 1024 or size < min_size_mb * 1024 * 1024:
                return None
            if keyword and keyword.lower() not in name.lower():
                return None
            if date_filter and file_info['mtime'] != "N/A":
                file_date = datetime.fromisoformat(file_info['mtime'].replace('Z', '+00:00')).date()
                start_date, end_date = date_filter
                if start_date and file_date < start_date:
                    return None
                if end_date and file_date > end_date:
                    return None

            # Calcular hashes y ADN digital
            if size <= max_size_mb * 1024 * 1024:
                file_info['hashes'] = await self._calculate_forensic_hashes(file_obj, size, entry.info.meta.addr)
                file_info['digital_dna'] = await self._generate_digital_dna(file_obj, size, file_info, name)

            # Carving de slack space
            if analyze_hidden:
                slack_data = await self._carve_slack_space(entry)
                if slack_data:
                    file_info['slack_space'] = len(slack_data)
                    print(f"{Fore.CYAN}{self.messages[self.language]['slack_space'].format(len(slack_data))}{Style.RESET_ALL}")

            # Extraer archivo
            if extract_dir and file_info['type'] == 'ARCHIVO':
                await self._extract_file(entry, extract_dir, name)

            return file_info
        except Exception as e:
            logging.error(f"Error procesando {name}: {e}")
            return None

    async def generate_report(self, output_file, format='json', compress=False, encrypt=False):
        """
        Genera un reporte forense en el formato especificado.

        Args:
            output_file (str): Archivo de destino.
            format (str): Formato de salida ('json', 'csv', 'xml', 'html').
            compress (bool): Comprimir el reporte en ZIP.
            encrypt (bool): Encriptar el reporte con AES.
        """
        if not self.found_items and not self.memory_results['processes']:
            print(f"{Fore.YELLOW}{self.messages[self.language]['no_matches']}{Style.RESET_ALL}")
            logging.warning("No se encontraron archivos ni artefactos de memoria para el reporte")
            return

        report = {
            'metadata': {
                'case': ', '.join(os.path.basename(path) for path in self.image_paths),
                'memory_image': self.memory_image,
                'date': datetime.now().isoformat(),
                'total_files': self.stats['files'],
                'total_directories': self.stats['directories'],
                'matched_files': len(self.found_items),
                'deleted_files': self.stats['deleted_files'],
                'partitions_analyzed': sum(len(parts) for parts in self.partitions),
                'extensions_found': dict(self.extension_stats),
                'memory_processes': len(self.memory_results['processes']),
                'memory_connections': len(self.memory_results['connections']),
                'memory_injections': len(self.memory_results['injections']),
                'encryption_key': self.encryption_key.decode() if encrypt else None
            },
            'disk_findings': self.found_items,
            'memory_findings': self.memory_results
        }

        try:
            Path(os.path.dirname(output_file)).mkdir(parents=True, exist_ok=True)
            temp_file = output_file + '.tmp'
            if format == 'json':
                async with aiofiles.open(temp_file, 'w') as f:
                    await f.write(json.dumps(report, indent=2, default=str))
            elif format == 'csv':
                async with aiofiles.open(temp_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=self.found_items[0].keys() if self.found_items else ['path'])
                    await f.write(','.join(self.found_items[0].keys()) + '\n' if self.found_items else 'path\n')
                    for item in self.found_items:
                        await f.write(','.join(str(v) for v in item.values()) + '\n')
            elif format == 'xml':
                root = ET.Element("AstraDeathReport")
                meta = ET.SubElement(root, "Metadata")
                for key, value in report['metadata'].items():
                    ET.SubElement(meta, key).text = str(value)
                disk_findings = ET.SubElement(root, "DiskFindings")
                for item in report['disk_findings']:
                    file_elem = ET.SubElement(disk_findings, "File")
                    for key, value in item.items():
                        ET.SubElement(file_elem, key).text = str(value)
                memory_findings = ET.SubElement(root, "MemoryFindings")
                for proc in report['memory_findings']['processes']:
                    proc_elem = ET.SubElement(memory_findings, "Process")
                    for key, value in proc.items():
                        ET.SubElement(proc_elem, key).text = str(value)
                ET.ElementTree(root).write(temp_file, encoding='unicode')
            elif format == 'html':
                env = Environment(loader=FileSystemLoader('.'))
                template = env.get_template('report_template.html')
                async with aiofiles.open(temp_file, 'w') as f:
                    await f.write(template.render(report=report))

            # Generar reporte de estadísticas de extensiones
            ext_report = output_file + '.extensions.csv'
            async with aiofiles.open(ext_report, 'w', newline='') as f:
                writer = csv.writer(f)
                await f.write('Extension,Count\n')
                for ext, count in self.extension_stats.items():
                    await f.write(f"{ext},{count}\n")

            # Generar reporte de memoria
            if self.memory_results['processes']:
                mem_report = output_file + '.memory.csv'
                async with aiofiles.open(mem_report, 'w', newline='') as f:
                    writer = csv.writer(f)
                    await f.write('Type,PID,Name,Details\n')
                    for proc in self.memory_results['processes']:
                        await f.write(f"Process,{proc['pid']},{proc['name']},Created: {proc['create_time']}\n")
                    for conn in self.memory_results['connections']:
                        await f.write(f"Connection,{conn['pid']},{conn['owner']},{conn['protocol']} {conn['local_addr']} -> {conn['remote_addr']}\n")
                    for inj in self.memory_results['injections']:
                        await f.write(f"Injection,{inj['pid']},{inj['process_name']},Address: {inj['address']}, Entropy: {inj['entropy']}\n")

            if encrypt:
                async with aiofiles.open(temp_file, 'rb') as f:
                    data = await f.read()
                encrypted_data = self.cipher.encrypt(data)
                async with aiofiles.open(output_file, 'wb') as f:
                    await f.write(encrypted_data)
                os.remove(temp_file)
            elif compress:
                with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                    zf.write(temp_file, os.path.basename(output_file))
                os.remove(temp_file)
            else:
                os.rename(temp_file, output_file)

            print(f"{Fore.GREEN}{self.messages[self.language]['report_generated'].format(output_file, format.upper())}{Style.RESET_ALL}")
            logging.info(f"Reporte generado: {output_file} ({format})")
        except Exception as e:
            logging.error(f"Error generando reporte: {e}")
            print(f"{Fore.RED}{self.messages[self.language]['report_error'].format(str(e))}{Style.RESET_ALL}")

    async def generate_chain_of_custody(self, output_file):
        """
        Genera un archivo de cadena de custodia.

        Args:
            output_file (str): Archivo de destino.
        """
        custody = {
            'case': ', '.join(os.path.basename(path) for path in self.image_paths),
            'memory_image': self.memory_image,
            'date': datetime.now().isoformat(),
            'image_hashes': {},
            'extracted_files': []
        }
        for path in self.image_paths:
            with open(path, 'rb') as f:
                hasher = hashlib.sha256()
                while chunk := f.read(1024*1024):
                    hasher.update(chunk)
                custody['image_hashes'][path] = hasher.hexdigest()

        if self.memory_image:
            with open(self.memory_image, 'rb') as f:
                hasher = hashlib.sha256()
                while chunk := f.read(1024*1024):
                    hasher.update(chunk)
                custody['image_hashes']['memory'] = hasher.hexdigest()

        for item in self.found_items:
            if item.get('hashes', {}).get('sha256'):
                custody['extracted_files'].append({
                    'path': item['path'],
                    'sha256': item['hashes']['sha256'],
                    'digital_dna': item.get('digital_dna', {}).get('dna_hash', 'N/A')
                })

        async with aiofiles.open(output_file, 'w') as f:
            await f.write(json.dumps(custody, indent=2))
        logging.info(f"Cadena de custodia generada: {output_file}")
        print(f"{Fore.GREEN}[✓] Cadena de custodia generada: {output_file}{Style.RESET_ALL}")

async def run_web_server(analyzer):
    """
    Inicia el servidor web para actualizaciones en tiempo real.

    Args:
        analyzer: Instancia de AstraDeathAnalyzer.
    """
    async def index(request):
        async with aiofiles.open('index.html', 'r') as f:
            return web.Response(text=await f.read(), content_type='text/html')

    analyzer.app.router.add_get('/', index)
    runner = web.AppRunner(analyzer.app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8080)
    await site.start()
    print(f"{Fore.CYAN}[*] Servidor web iniciado en http://localhost:8080{Style.RESET_ALL}")

async def tui_interface(analyzer):
    """
    Interfaz TUI para configurar parámetros y mostrar resultados.

    Args:
        analyzer: Instancia de AstraDeathAnalyzer.
    """
    session = PromptSession(multiline=False, prompt_continuation='> ')
    completer = WordCompleter(list(KNOWN_EXTENSIONS.keys()) + ['all', 'json', 'csv', 'xml', 'html', 'sí', 'no'])
    
    print(f"{Fore.CYAN}Bienvenido a AstraDeath v4.3 - Interfaz Forense Interactiva (Nivel NSA/FBI){Style.RESET_ALL}")
    
    params = {
        'image_paths': analyzer.image_paths,
        'memory_image': await session.prompt_async(
            HTML('<ansicyan>Imagen de memoria (opcional):</ansicyan> '), default='' if not analyzer.memory_image else analyzer.memory_image
        ) or None,
        'extensions': (await session.prompt_async(
            HTML('<ansicyan>Extensiones a buscar (separadas por espacio, ej: .docx .pdf, o "all"):</ansicyan> '),
            default='.docx .pdf .xlsx .db .log .config', completer=completer
        )).split(),
        'path': await session.prompt_async(
            HTML('<ansicyan>Ruta inicial:</ansicyan> '), default='/'
        ),
        'output': await session.prompt_async(
            HTML('<ansicyan>Archivo de salida:</ansicyan> '), default='report.json'
        ),
        'format': await session.prompt_async(
            HTML('<ansicyan>Formato de salida (json, csv, xml, html):</ansicyan> '),
            default='json', completer=completer
        ),
        'max_size': int(await session.prompt_async(
            HTML('<ansicyan>Tamaño máximo (MB):</ansicyan> '), default='100'
        )),
        'min_size': int(await session.prompt_async(
            HTML('<ansicyan>Tamaño mínimo (MB):</ansicyan> '), default='0'
        )),
        'date_start': await session.prompt_async(
            HTML('<ansicyan>Fecha inicial (YYYY-MM-DD, opcional):</ansicyan> '), default=''
        ) or None,
        'date_end': await session.prompt_async(
            HTML('<ansicyan>Fecha final (YYYY-MM-DD, opcional):</ansicyan> '), default=''
        ) or None,
        'keyword': await session.prompt_async(
            HTML('<ansicyan>Palabra clave (opcional):</ansicyan> '), default=''
        ) or None,
        'depth': int(await session.prompt_async(
            HTML('<ansicyan>Profundidad de directorios:</ansicyan> '), default='5'
        )),
        'extract_dir': await session.prompt_async(
            HTML('<ansicyan>Directorio de extracción (opcional):</ansicyan> '), default=''
        ) or None,
        'recover_deleted': (await session.prompt_async(
            HTML('<ansicyan>Recuperar archivos eliminados (sí/no):</ansicyan> '), default='no', completer=completer
        )).lower() == 'sí',
        'analyze_hidden': (await session.prompt_async(
            HTML('<ansicyan>Analizar metadatos ocultos (sí/no):</ansicyan> '), default='no', completer=completer
        )).lower() == 'sí',
        'detect_steg': (await session.prompt_async(
            HTML('<ansicyan>Detectar esteganografía (sí/no):</ansicyan> '), default='no', completer=completer
        )).lower() == 'sí',
        'compress': (await session.prompt_async(
            HTML('<ansicyan>Comprimir reporte (sí/no):</ansicyan> '), default='no', completer=completer
        )).lower() == 'sí',
        'encrypt': (await session.prompt_async(
            HTML('<ansicyan>Encriptar reporte (sí/no):</ansicyan> '), default='no', completer=completer
        )).lower() == 'sí'
    }

    if params['memory_image']:
        analyzer.memory_image = params['memory_image']

    if params['date_start']:
        params['date_start'] = validate_date(params['date_start'])
    if params['date_end']:
        params['date_end'] = validate_date(params['date_end'])

    print(f"{Fore.CYAN}{analyzer.messages[analyzer.language]['parameters']}{Style.RESET_ALL}")
    for key, value in params.items():
        print(f"    - {key}: {value}")

    await analyzer.scan_filesystem(
        path=params['path'],
        extensions=params['extensions'],
        max_size_mb=params['max_size'],
        min_size_mb=params['min_size'],
        depth=params['depth'],
        date_filter=(params['date_start'], params['date_end']) if params['date_start'] or params['date_end'] else None,
        keyword=params['keyword'],
        extract_dir=params['extract_dir'],
        recover_deleted=params['recover_deleted'],
        analyze_hidden=params['analyze_hidden'],
        detect_steg=params['detect_steg']
    )

    await analyzer.generate_report(params['output'], params['format'], params['compress'], params['encrypt'])
    await analyzer.generate_chain_of_custody(params['output'] + '.custody.json')

def show_banner():
    """
    Muestra el banner de la herramienta.
    """
    print(f"{Fore.CYAN}")
    print(r"""
    █████╗ ███████╗████████╗██████╗  █████╗ ███████╗ █████╗ ████████╗██╗  ██╗
    ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═════╝██║  ██║
    ███████║███████╗   ██║   ██████╔╝███████║█████╗  █████╗  █████╗   ███████║
    ██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██╔══╝   ██╔══██║
    ██║  ██║███████║   ██║   ██║  ██║██║  ██║███████╗███████╗██║      ██║  ██║
    ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═╝  ╚═╝
    """)
    print(f"    Herramienta Forense de Análisis Profundo | v4.3 | AstraDeath (Nivel NSA/FBI con Análisis de Memoria){Style.RESET_ALL}\n")

def validate_date(date_str):
    """
    Valida un formato de fecha (YYYY-MM-DD).

    Args:
        date_str (str): Fecha a validar.

    Returns:
        datetime.date: Fecha validada.
    """
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        raise argparse.ArgumentTypeError("Formato de fecha inválido. Use YYYY-MM-DD")

async def main():
    show_banner()
    
    parser = argparse.ArgumentParser(
        description='AstraDeath - Análisis forense avanzado (Nivel NSA/FBI con Análisis de Memoria)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('imagen', nargs='+', help='Ruta(s) a la(s) imagen(es) forense(s) (RAW/DD/E01)')
    parser.add_argument('--memory-image', help='Ruta a la imagen de memoria (RAW/VMEM)', default=None)
    parser.add_argument('--tui', action='store_true', help='Usar interfaz TUI')
    parser.add_argument('--language', choices=['es', 'en'], default='es', help='Idioma de la interfaz')
    parser.add_argument('--log-file', default='astradeath.log', help='Archivo de log para auditoría')

    args = parser.parse_args()

    analyzer = AstraDeathAnalyzer(args.imagen, args.memory_image, args.log_file, args.language)
    analyzer._install_dependencies()

    if args.tui:
        await asyncio.gather(run_web_server(analyzer), tui_interface(analyzer))
    else:
        print(f"{Fore.RED}[!] Modo CLI no implementado en esta versión. Usa --tui para la interfaz interactiva.{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
