using System;
using System.IO;
using System.Linq;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

namespace ProjectSafe {
 public static class Program {
  [STAThread] public static void Main(string[] args) {
   Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
   if(args.Length>0 && args[0]=="--test") {Tests.Run(args[1]);return;}
   if(args.Length>0 && args[0]=="--make-demo") {Tests.Demo(args[1]);return;}
   if(args.Length>0 && args[0]=="--verify") {
    try {int n=Vault.Verify(args[1],CancellationToken.None,null);File.WriteAllText(args[2],Vault.Json().Serialize(new{VerifiedFiles=n,Status="OK"}));}
    catch(Exception ex){File.WriteAllText(args[2],Vault.Json().Serialize(new{Error=ex.Message}));Environment.ExitCode=1;}return;
   }
   if(args.Length>0 && args[0]=="--backup") {
    try {var scan=Vault.Inspect(args[1],CancellationToken.None,null);string bundle=Vault.Pack(scan,args[2],CancellationToken.None,null);int verified=Vault.Verify(bundle,CancellationToken.None,null);File.WriteAllText(args[3],Vault.Json().Serialize(new{Bundle=bundle,VerifiedFiles=verified,Bytes=scan.Bytes,Findings=scan.Findings}));}
    catch(Exception ex){File.WriteAllText(args[3],Vault.Json().Serialize(new{Error=ex.Message}));Environment.ExitCode=1;}return;
   }
   if(args.Length>0 && args[0]=="--scan") {
    try {var s=Vault.Inspect(args[1],CancellationToken.None,null);File.WriteAllText(args[2],Vault.Json().Serialize(s));}
    catch(Exception ex){File.WriteAllText(args[2],Vault.Json().Serialize(new{Error=ex.Message}));Environment.ExitCode=1;}return;
   }
   var form=new MainForm();
   if(args.Length>0 && args[0]=="--ui-smoke") {
    form.Shown+=async delegate {
     try {await form.TestFlow(args[1],args[2]);using(var bmp=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bmp,new Rectangle(0,0,bmp.Width,bmp.Height));bmp.Save(args[3]);}File.WriteAllText(args[4],"UI_SCAN_COPY_VERIFY_OK");}
     catch(Exception ex){File.WriteAllText(args[4],ex.ToString());Environment.ExitCode=1;}finally{form.Close();}
    };Application.Run(form);return;
   }
   if(args.Length>0 && args[0]=="--preview") {
    form.LoadPreview(args[1]);form.Show();Application.DoEvents();
    using(var bmp=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(bmp,new Rectangle(0,0,bmp.Width,bmp.Height));bmp.Save(args[2]);}form.Close();return;
   }
   if(args.Length>0 && args[0]=="--demo")form.LoadPreview(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"Пример проекта"));
   Application.Run(form);
  }
 }
 public class MainForm:Form {
  static Color Bg=Color.FromArgb(18,22,28),PanelBg=Color.FromArgb(25,31,39),Line=Color.FromArgb(48,58,69),Ink=Color.FromArgb(232,238,240),Muted=Color.FromArgb(153,169,180),Mint=Color.FromArgb(124,231,192),Amber=Color.FromArgb(246,198,116);
  TextBox source,destination;
  Button scanButton,saveButton,cancelButton,sourceButton,destinationButton,verifyButton,openButton,demoButton;
  Label headline,caption,status,count,size,media,coverage;
  ListView files,findings;
  TabControl tabs;
  ProgressBar bar;
  Panel side;
  CancellationTokenSource cancel;
  Scan current;
  bool busy;
  int stage=1;
  string lastBundle;
  List<Control> inputs=new List<Control>();
  public MainForm() {
   Text="Сейф проекта · рабочая версия 0.4";ClientSize=new Size(1120,790);MinimumSize=new Size(1100,800);
   StartPosition=FormStartPosition.CenterScreen;BackColor=Bg;ForeColor=Ink;Font=new Font("Segoe UI",10);AutoScaleMode=AutoScaleMode.Dpi;
   Icon=SystemIcons.Shield;
   side=new Panel{Location=new Point(0,0),Size=new Size(224,790),Anchor=AnchorStyles.Left|AnchorStyles.Top|AnchorStyles.Bottom,BackColor=PanelBg};Controls.Add(side);side.Paint+=PaintSide;
   var main=new Panel{Location=new Point(248,0),Size=new Size(844,790),Anchor=AnchorStyles.Top|AnchorStyles.Bottom|AnchorStyles.Left|AnchorStyles.Right};Controls.Add(main);
   LabelAt(main,"ТВОЯ РАБОТА. В ОДНОМ МЕСТЕ.",0,25,800,22,9,Muted);
   headline=LabelAt(main,"Сохрани проект целиком",0,54,800,45,27,Ink);
   caption=LabelAt(main,"Отдельная копия исходников с проверкой содержимого каждого файла.",1,107,810,25,10,Muted);
   LabelAt(main,"ПАПКА ПРОЕКТА",0,153,800,20,9,Muted);
   source=PathBox(main,0,180,660);sourceButton=ButtonAt(main,"Выбрать…",674,177,162,36,false);
   sourceButton.Click+=delegate{Pick(source);};source.TextChanged+=delegate{if(!busy)ResetScan();};
   LabelAt(main,"КУДА СОХРАНИТЬ КОПИЮ",0,229,800,20,9,Muted);
   destination=PathBox(main,0,256,660);destination.Text=Directory.Exists("D:\\")?"D:\\ProjectSafe":Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),"ProjectSafe");
   destinationButton=ButtonAt(main,"Выбрать…",674,253,162,36,false);destinationButton.Click+=delegate{Pick(destination);};
   count=Card(main,"ИСХОДНЫХ ФАЙЛОВ",0,310,263);size=Card(main,"ОБЪЁМ ИСХОДНИКОВ",279,310,263);media=Card(main,"МЕДИАФАЙЛОВ",558,310,278);
   coverage=LabelAt(main,"Сначала выбери папку и нажми «Проверить проект».",0,401,830,40,9,Muted);
   tabs=new TabControl{Location=new Point(0,449),Size=new Size(836,211),Anchor=AnchorStyles.Top|AnchorStyles.Bottom|AnchorStyles.Left|AnchorStyles.Right,Font=new Font("Segoe UI",10)};
   var tabFiles=new TabPage("Файлы"){BackColor=PanelBg};var tabFindings=new TabPage("Что проверить"){BackColor=PanelBg};
   tabs.TabPages.AddRange(new[]{tabFiles,tabFindings});main.Controls.Add(tabs);
   files=MakeList(tabFiles,new[]{"Файл","Тип","Размер","Расположение"},new[]{430,95,90,170});
   findings=MakeList(tabFindings,new[]{"Статус","Проект / файл","Подробности"},new[]{110,180,850});
   files.DoubleClick+=delegate{if(files.SelectedItems.Count>0){var item=files.SelectedItems[0].Tag as Item;if(item!=null&&File.Exists(item.Source))Process.Start("explorer.exe","/select,\""+item.Source+"\"");}};
   bar=new ProgressBar{Location=new Point(0,681),Size=new Size(836,5),Anchor=AnchorStyles.Left|AnchorStyles.Right|AnchorStyles.Bottom,Style=ProgressBarStyle.Continuous};main.Controls.Add(bar);
   status=LabelAt(main,"Исходные файлы останутся на месте.",0,695,620,23,9,Muted);status.Anchor=AnchorStyles.Left|AnchorStyles.Bottom;
   scanButton=ButtonAt(main,"Проверить проект",0,735,201,38,false);scanButton.Anchor=AnchorStyles.Left|AnchorStyles.Bottom;scanButton.Click+=async delegate{await Inspect();};
   saveButton=ButtonAt(main,"Сохранить копию",217,735,213,38,true);saveButton.Anchor=AnchorStyles.Left|AnchorStyles.Bottom;saveButton.Enabled=false;saveButton.Click+=async delegate{await Save();};
   cancelButton=ButtonAt(main,"Отмена",446,735,105,38,false);cancelButton.Anchor=AnchorStyles.Left|AnchorStyles.Bottom;cancelButton.Enabled=false;cancelButton.Click+=delegate{if(cancel!=null)cancel.Cancel();};
   openButton=ButtonAt(main,"Открыть копию",570,735,266,38,false);openButton.Anchor=AnchorStyles.Right|AnchorStyles.Bottom;openButton.Enabled=false;openButton.Click+=delegate{if(Directory.Exists(lastBundle))Process.Start("explorer.exe",lastBundle);};
   verifyButton=ButtonAt(side,"Проверить готовую копию",18,609,188,46,false);verifyButton.Anchor=AnchorStyles.Left|AnchorStyles.Bottom;verifyButton.Font=new Font("Segoe UI",9);verifyButton.Click+=async delegate{await Verify();};
   demoButton=ButtonAt(side,"Попробовать на примере",18,666,188,38,false);demoButton.Anchor=AnchorStyles.Left|AnchorStyles.Bottom;demoButton.Font=new Font("Segoe UI",9);demoButton.Click+=async delegate{source.Text=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"Пример проекта");await Inspect();};
   LabelAt(side,"ЛОКАЛЬНО · БЕЗ АККАУНТА",20,747,202,20,8,Muted).Anchor=AnchorStyles.Left|AnchorStyles.Bottom;
   inputs.AddRange(new Control[]{source,destination,sourceButton,destinationButton,scanButton,verifyButton,demoButton});
   FormClosing+=delegate(object sender,FormClosingEventArgs e){if(busy){cancel.Cancel();e.Cancel=true;status.Text="Отменяю операцию. Дождись завершения перед закрытием.";}};
  }
  void PaintSide(object sender,PaintEventArgs e) {
   var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;
   using(var p=new Pen(Mint,2)){g.DrawRectangle(p,23,31,30,30);g.DrawEllipse(p,32,40,12,12);g.DrawLine(p,38,41,38,51);}
   using(var f=new Font("Segoe UI",13,FontStyle.Bold))g.DrawString("Сейф проекта",f,new SolidBrush(Ink),66,31);
   using(var f=new Font("Segoe UI",9))g.DrawString("РАБОЧАЯ ВЕРСИЯ 0.4",f,new SolidBrush(Muted),23,84);
   string[] titles={"Выбери проект","Проверь состав","Сохрани копию"};string[] hints={"Папка с твоими файлами","Медиа, связи и замечания","С проверкой SHA-256"};
   for(int i=0;i<3;i++){
    int y=178+i*91;var active=stage==i+1;var c=active?Mint:Muted;
    using(var p=new Pen(active?Mint:Line,1))g.DrawEllipse(p,24,y,28,28);
    using(var f=new Font("Segoe UI",10,FontStyle.Bold))g.DrawString((i+1).ToString(),f,new SolidBrush(c),32,y+4);
    using(var f=new Font("Segoe UI",10,FontStyle.Bold))g.DrawString(titles[i],f,new SolidBrush(c),65,y-1);
    using(var f=new Font("Segoe UI",8.5f))g.DrawString(hints[i],f,new SolidBrush(Muted),65,y+24);
   }
   using(var p=new Pen(Line))g.DrawLine(p,23,473,200,473);
   using(var f=new Font("Segoe UI",9))g.DrawString("Твои файлы остаются\nна твоём компьютере.\n\nБез загрузки в облако.\nБез изменения исходников.",f,new SolidBrush(Muted),23,493);
  }
  static Label LabelAt(Control parent,string text,int x,int y,int w,int h,float fs,Color color){var l=new Label{Text=text,Location=new Point(x,y),Size=new Size(w,h),ForeColor=color,Font=new Font("Segoe UI",fs),BackColor=Color.Transparent};parent.Controls.Add(l);return l;}
  static TextBox PathBox(Control p,int x,int y,int w){var t=new TextBox{Location=new Point(x,y),Size=new Size(w,31),BackColor=PanelBg,ForeColor=Ink,BorderStyle=BorderStyle.FixedSingle,Font=new Font("Segoe UI",11)};p.Controls.Add(t);return t;}
  static Button ButtonAt(Control p,string text,int x,int y,int w,int h,bool primary){var b=new Button{Text=text,Location=new Point(x,y),Size=new Size(w,h),FlatStyle=FlatStyle.Flat,BackColor=primary?Mint:PanelBg,ForeColor=primary?Bg:Ink,Cursor=Cursors.Hand,Font=new Font("Segoe UI",10,primary?FontStyle.Bold:FontStyle.Regular),UseVisualStyleBackColor=false};b.FlatAppearance.BorderColor=primary?Mint:Line;p.Controls.Add(b);return b;}
  static Label Card(Control p,string title,int x,int y,int w){var c=new Panel{Location=new Point(x,y),Size=new Size(w,80),BackColor=PanelBg};p.Controls.Add(c);LabelAt(c,title,16,12,w-24,20,8,Muted);return LabelAt(c,"—",14,34,w-24,39,23,Ink);}
  static ListView MakeList(Control parent,string[] titles,int[] widths){var v=new ListView{Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,HideSelection=false,BackColor=PanelBg,ForeColor=Ink,BorderStyle=BorderStyle.None,Font=new Font("Segoe UI",9)};for(int i=0;i<titles.Length;i++)v.Columns.Add(titles[i],widths[i]);parent.Controls.Add(v);return v;}
  static string Bytes(long b){string[] u={"Б","КБ","МБ","ГБ","ТБ"};double n=b;int i=0;while(n>=1024&&i<4){n/=1024;i++;}return n.ToString(i==0?"0":"0.##")+" "+u[i];}
  void Pick(TextBox target){using(var dialog=new FolderBrowserDialog{Description=target==source?"Выбери папку проекта":"Выбери место для отдельной копии",ShowNewFolderButton=true}){if(Directory.Exists(target.Text))dialog.SelectedPath=target.Text;if(dialog.ShowDialog(this)==DialogResult.OK)target.Text=dialog.SelectedPath;}}
  void ResetScan(){current=null;saveButton.Enabled=false;files.Items.Clear();findings.Items.Clear();count.Text=size.Text=media.Text="—";coverage.Text="Проверка папки ещё не выполнена.";stage=1;side.Invalidate();}
  void SetBusy(bool value){busy=value;foreach(var c in inputs)c.Enabled=!value;saveButton.Enabled=!value&&current!=null&&!current.Blocked&&current.Files.Count>0;cancelButton.Enabled=value;if(value){cancel=new CancellationTokenSource();bar.Value=0;}else{bar.Style=ProgressBarStyle.Continuous;cancel.Dispose();cancel=null;}}
  Progress<ProgressInfo> Reporter(){var last=DateTime.MinValue;return new Progress<ProgressInfo>(p=>{if(!busy)return;if((DateTime.UtcNow-last).TotalMilliseconds<90)return;last=DateTime.UtcNow;status.Text=p.Message;if(p.Total>0){bar.Style=ProgressBarStyle.Continuous;bar.Value=(int)Math.Max(0,Math.Min(100,100.0*p.Done/p.Total));}else bar.Style=ProgressBarStyle.Marquee;});}
  void ShowScan(Scan s){
   count.Text=s.Files.Count.ToString("N0");size.Text=Bytes(s.Bytes);media.Text=s.Files.Count(f=>f.Category=="Видео"||f.Category=="Аудио"||f.Category=="Графика").ToString("N0");
   files.BeginUpdate();files.Items.Clear();foreach(var f in s.Files){var row=new ListViewItem(new[]{f.Relative,f.Category,Bytes(f.Size),f.Linked?"Внешний файл":"В папке"}){Tag=f};files.Items.Add(row);}files.EndUpdate();
   findings.BeginUpdate();findings.Items.Clear();foreach(var f in s.Findings){var row=new ListViewItem(new[]{f.Level,f.File,f.Message});if(f.Level=="Ошибка"||f.Level=="Не найден")row.ForeColor=Color.FromArgb(255,155,155);else if(f.Level!="Информация")row.ForeColor=Amber;findings.Items.Add(row);}findings.EndUpdate();
   int missing=s.Findings.Count(x=>x.Level=="Не найден");
   int linked=s.Files.Count(x=>x.Linked);
   int ready=s.ReadyCount;
   coverage.Text=s.Blocked?"Есть ошибки чтения. Исправь их перед сохранением.":missing>0?"Не найдено исходников: "+missing+". Сохраним доступные файлы; для неполных проектов отдельные копии не создаются.":ready>0?"Проектов для переноса: "+ready+". Внешних файлов: "+linked+". Оригиналы сохранятся отдельно.":"Готово к копированию. Сбор связей Adobe/XML смотри в замечаниях; перепривязка вручную.";
   coverage.ForeColor=s.Blocked||missing>0||linked>0?Amber:Muted;
   tabs.TabPages[0].Text="Файлы · "+s.Files.Count;tabs.TabPages[1].Text="Что проверить · "+s.Findings.Count;
   stage=2;side.Invalidate();
  }
  async Task Inspect(){
   if(String.IsNullOrWhiteSpace(source.Text)){Pick(source);if(String.IsNullOrWhiteSpace(source.Text))return;}
   ResetScan();SetBusy(true);var reporter=Reporter();string path=source.Text;
   try {var s=await Task.Run(()=>Vault.Inspect(path,cancel.Token,p=>((IProgress<ProgressInfo>)reporter).Report(p)));current=s;ShowScan(s);status.Text="Проверка состава завершена. Исходники не изменены.";bar.Value=100;}
   catch(Exception ex){Error(ex);}
   finally{SetBusy(false);}
  }
  async Task Save(){
   if(current==null)return;
   if(current.Findings.Any(x=>x.Level=="Не найден")&&MessageBox.Show(this,"Часть исходников не найдена. Сохранить доступные файлы и список замечаний?","Есть недостающие файлы",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;
   SetBusy(true);var reporter=Reporter();string parent=destination.Text;stage=3;side.Invalidate();
   try {lastBundle=await Task.Run(()=>Vault.Pack(current,parent,cancel.Token,p=>((IProgress<ProgressInfo>)reporter).Report(p)));bar.Value=100;headline.Text="Копия файлов проверена";status.Text=current.ReadyCount>0?"Готово. Открывай проект из Ready. Переноси весь сейф целиком.":"Готово. Открой копию и прочитай замечания перед переносом проекта.";openButton.Enabled=true;}
   catch(Exception ex){Error(ex);}
   finally{SetBusy(false);}
  }
  async Task Verify(){
   using(var dialog=new FolderBrowserDialog{Description="Выбери папку готовой копии с manifest.json"}){
    if(dialog.ShowDialog(this)!=DialogResult.OK)return;string path=dialog.SelectedPath;SetBusy(true);var reporter=Reporter();
    try{int n=await Task.Run(()=>Vault.Verify(path,cancel.Token,p=>((IProgress<ProgressInfo>)reporter).Report(p)));bar.Value=100;status.Text="Проверено файлов: "+n+". Изменений содержимого не обнаружено.";MessageBox.Show(this,status.Text,"Копия цела",MessageBoxButtons.OK,MessageBoxIcon.Information);}
    catch(Exception ex){Error(ex);}finally{SetBusy(false);}
   }
  }
  void Error(Exception ex){bar.Value=0;status.Text=ex is OperationCanceledException?"Проверка отменена.":"Операция не завершена. Подробности в сообщении.";MessageBox.Show(this,ex.Message,"Сейф проекта",MessageBoxButtons.OK,MessageBoxIcon.Information);}
  public void LoadPreview(string path){source.Text=path;current=Vault.Inspect(path,CancellationToken.None,null);ShowScan(current);saveButton.Enabled=!current.Blocked;status.Text="Пример: проект, локальный кадр и внешний звуковой файл.";}
  public async Task TestFlow(string src,string dest){source.Text=src;destination.Text=dest;await Inspect();if(current==null||!saveButton.Enabled)throw new Exception("UI scan failed");await Save();if(lastBundle==null||!openButton.Enabled)throw new Exception("UI save failed");int n=await Task.Run(()=>Vault.Verify(lastBundle,CancellationToken.None,null));if(n!=current.Files.Count+current.ReadyCount)throw new Exception("UI verify failed");}
 }
}
