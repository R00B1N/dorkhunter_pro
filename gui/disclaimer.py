"""Aviso legal de primera ejecución y ventana de consulta posterior."""
from __future__ import annotations

import customtkinter as ctk

from config import APP_NAME, APP_VERSION
from gui.theme import COLORS, font

DISCLAIMER_TEXT = """DORKHUNTER PRO — AVISO LEGAL Y USO RESPONSABLE

1. OBJETO DE LA HERRAMIENTA
DorkHunter Pro es una utilidad de auditoría y OSINT cuyo núcleo es PASIVO:
genera consultas en motores de búsqueda para localizar URLs con parámetros y
comprueba si la respuesta del servidor revela mensajes de error SQL (una
única comilla simple). El triaje pasivo NO explota, NO extrae datos y NO
ejecuta técnicas de Blind SQLi ni Time-Based.

La aplicación incluye una fase adicional OPCIONAL y DESACTIVADA por defecto
de verificación con SQLMap. Si la activas, SQLMap enviará payloads reales,
puede generar cientos de peticiones y, si activas "--dbs", EXTRAERÁ bases
de datos del servidor. Esa fase es una prueba ACTIVA de explotación: úsala
exclusivamente dentro de un engagement autorizado.

2. AUTORIZACIÓN EXPRESA
El uso de esta herramienta está permitido únicamente sobre:
  • Sistemas de tu propiedad, o
  • Sistemas sobre los que dispongas de autorización escrita y vigente
    (contrato de pentesting, programa de bug bounty, orden judicial, etc.).

Esto aplica con mayor razón a la fase con SQLMap: atacar sistemas de
terceros sin autorización es un delito, con o sin proxychains. En Colombia,
la Ley 1273 de 2009 tipifica el acceso abusivo a sistemas informáticos;
legislaciones equivalentes existen en la mayoría de países.

3. ALCANCE TÉCNICO
  • Fase pasiva: una petición GET de línea base y una petición GET con una
    comilla simple; espaciado mínimo de 1,5 s por host; límite de URLs y de
    tamaño de respuesta; parámetros de sesión, login, pago o borrado
    omitidos.
  • Fase activa (solo si la activas): SQLMap como subproceso separado, con
    las URLs que elijas verificar (por defecto solo los hallazgos
    "posible_vuln"); proxychains4 y --dbs son opcionales y están apagados
    por defecto. Si proxychains4 está activado y su binario no existe, la
    fase se aborta: nunca se ejecuta "sin proxy" por accidente.

4. DATOS Y PRIVACIDAD
Los hallazgos, contactos WHOIS, veredictos de SQLMap y reportes se guardan
LOCALMENTE en la carpeta del proyecto (data/ y reports/). La herramienta no
envía datos a servidores del autor. Las consultas a los motores de búsqueda,
WHOIS y a los sitios objetivo sí salen a Internet y pueden quedar
registradas por esos terceros.

5. LIMITACIÓN DE RESPONSABILIDAD
El autor no se hace responsable del uso indebido, de los daños derivados de
interpretar un falso positivo como vulnerabilidad confirmada, de las
consecuencias de ejecutar la fase activa contra sistemas sin autorización,
ni del incumplimiento de la legislación aplicable por parte del usuario.

6. ACEPTACIÓN
Al pulsar "Aceptar y continuar" confirmas que has leído este aviso, que eres
mayor de edad y que utilizarás la herramienta exclusivamente en el marco de
una autorización válida y de la divulgación responsable.
"""


class DisclaimerDialog(ctk.CTkToplevel):
    def __init__(self, master: ctk.CTk) -> None:
        super().__init__(master)
        self.accepted = False
        self.title("Aviso legal · DorkHunter Pro")
        self.geometry("760x640")
        self.resizable(False, False)
        self.transient(master)
        self.configure(fg_color=COLORS["bg"])
        self.protocol("WM_DELETE_WINDOW", self._reject)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=26, pady=(22, 8))
        ctk.CTkLabel(
            header,
            text="Uso responsable y marco legal",
            font=font(20, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            header,
            text="Debes aceptar este aviso para utilizar la aplicación.",
            font=font(12),
            text_color=COLORS["muted"],
        ).pack(anchor="w", pady=(2, 0))

        self.text = ctk.CTkTextbox(
            self,
            fg_color=COLORS["panel"],
            border_width=1,
            border_color=COLORS["border"],
            corner_radius=10,
            text_color=COLORS["text"],
            font=font(11, mono=True),
            wrap="word",
        )
        self.text.grid(row=1, column=0, sticky="nsew", padx=26, pady=8)
        self.text.insert("1.0", DISCLAIMER_TEXT)
        self.text.configure(state="disabled")

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=26, pady=(8, 22))
        footer.grid_columnconfigure(0, weight=1)

        self.check_var = ctk.BooleanVar(value=False)
        self.check = ctk.CTkCheckBox(
            footer,
            text="He leído el aviso y acepto usarlo solo con autorización.",
            variable=self.check_var,
            command=self._toggle,
            font=font(12),
            text_color=COLORS["text"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border"],
            checkmark_color=COLORS["accent_text"],
        )
        self.check.grid(row=0, column=0, sticky="w", pady=(0, 14))

        buttons = ctk.CTkFrame(footer, fg_color="transparent")
        buttons.grid(row=1, column=0, sticky="e")

        ctk.CTkButton(
            buttons,
            text="Rechazar y salir",
            width=150,
            height=40,
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border"],
            hover_color=COLORS["panel_alt"],
            text_color=COLORS["muted"],
            command=self._reject,
        ).pack(side="left", padx=(0, 10))

        self.accept_button = ctk.CTkButton(
            buttons,
            text="Aceptar y continuar",
            width=190,
            height=40,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            font=font(12, "bold"),
            state="disabled",
            command=self._accept,
        )
        self.accept_button.pack(side="left")

        self.after(60, self._center)
        self.after(120, self.grab_set)

    # ------------------------------------------------------------------
    def _toggle(self) -> None:
        self.accept_button.configure(
            state="normal" if self.check_var.get() else "disabled"
        )

    def _accept(self) -> None:
        if not self.check_var.get():
            return
        self.accepted = True
        self.grab_release()
        self.destroy()

    def _reject(self) -> None:
        self.accepted = False
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

    def _center(self) -> None:
        self.update_idletasks()
        width, height = 760, 640
        x = self.master.winfo_rootx() + (self.master.winfo_width() - width) // 2
        y = self.master.winfo_rooty() + (self.master.winfo_height() - height) // 2
        self.geometry(f"{width}x{height}+{max(x, 0)}+{max(y, 0)}")


class LegalNoticeWindow(ctk.CTkToplevel):
    """Consulta del aviso legal una vez aceptado."""

    def __init__(self, master: ctk.CTk) -> None:
        super().__init__(master)
        self.title(f"Aviso legal · {APP_NAME} v{APP_VERSION}")
        self.geometry("720x560")
        self.configure(fg_color=COLORS["bg"])
        self.transient(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            self,
            text="Aviso legal y uso responsable",
            font=font(18, "bold"),
            text_color=COLORS["text"],
        ).grid(row=0, column=0, sticky="w", padx=24, pady=(20, 8))

        box = ctk.CTkTextbox(
            self,
            fg_color=COLORS["panel"],
            border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text"],
            font=font(11, mono=True),
            wrap="word",
        )
        box.grid(row=1, column=0, sticky="nsew", padx=24, pady=8)
        box.insert("1.0", DISCLAIMER_TEXT)
        box.configure(state="disabled")

        ctk.CTkButton(
            self,
            text="Cerrar",
            width=120,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color=COLORS["accent_text"],
            command=self.destroy,
        ).grid(row=2, column=0, sticky="e", padx=24, pady=(8, 20))
