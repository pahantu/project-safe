using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Threading;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace ProjectSafe {
 public class Item {
  public string Source, Relative, Category;
  public long Size, Stamp;
  public bool Linked;
 }
 public class Finding {
  public string Level, File, Message;
  public Finding(){}
  public Finding(string level,string file,string message){Level=level;File=file;Message=message;}
 }
 public class Scan {
  public string Root;
  public List<Item> Files=new List<Item>();
  public List<string> Directories=new List<string>();
  public List<Finding> Findings=new List<Finding>();
  public List<MltPlan> MltPlans=new List<MltPlan>();
  public List<OspPlan> OspPlans=new List<OspPlan>();
  public int ReadyCount {get{return MltPlans.Count(x=>x.CanRewrite)+OspPlans.Count(x=>x.CanRewrite);}}
  public int Projects;
  public long Bytes { get { return Files.Sum(x=>x.Size); } }
  public bool Blocked { get { return Findings.Any(x=>x.Level=="Ошибка"); } }
 }
 public class SavedItem {
  public string Path, SHA256, Original;
  public long Size;
  public bool Derived;
 }
 public class MltReference {
  public int Index;
  public string Source, Prefix;
 }
 public class MltPlan {
  public string Source, Relative, Editor="Shotcut";
  public bool CanRewrite=true;
  public List<MltReference> References=new List<MltReference>();
 }
 public class DerivedProject {
  public string Original, Path, Editor;
  public int RewrittenReferences;
 }
 public class Manifest {
  public string Format="ProjectSafe/1", CreatedUtc, Source, Status;
  public List<SavedItem> Files=new List<SavedItem>();
  public List<string> Directories=new List<string>();
  public List<Finding> Findings=new List<Finding>();
  public List<DerivedProject> DerivedProjects=new List<DerivedProject>();
 }
 public class ProgressInfo {
  public long Done, Total;
  public string Message;
  public ProgressInfo(long done,long total,string message){Done=done;Total=total;Message=message;}
 }
 public static partial class Vault {
  public static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=64*1024*1024,RecursionLimit=100};}
  public static string Hash(string path) {return Hash(path,CancellationToken.None);}
  public static string Hash(string path,CancellationToken token) {
   using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))
   using(var h=SHA256.Create()){
    byte[] buffer=new byte[1024*1024];int n;
    while((n=f.Read(buffer,0,buffer.Length))>0){token.ThrowIfCancellationRequested();h.TransformBlock(buffer,0,n,buffer,0);}
    h.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(h.Hash).Replace("-","").ToLowerInvariant();
   }
  }
  public static string Normalize(string path){return System.IO.Path.GetFullPath(path).TrimEnd('\\','/');}
  public static bool Inside(string file,string dir){return Normalize(file).StartsWith(Normalize(dir)+"\\",StringComparison.OrdinalIgnoreCase);}
  public static void NoLinks(string path) {
   var p=Path.GetFullPath(path);
   if(p.StartsWith("\\\\",StringComparison.Ordinal))throw new IOException("Сетевые пути в этой версии не поддерживаются. Выбери локальную папку.");
   var drive=new DriveInfo(Path.GetPathRoot(p));
   if(drive.DriveType==DriveType.Network)throw new IOException("Сетевые диски в этой версии не поддерживаются.");
   while(!String.IsNullOrEmpty(p)) {
    if((File.Exists(p)||Directory.Exists(p)) && (File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)
     throw new IOException("Путь проходит через ссылку на другую папку: "+p+". Выбери настоящее расположение.");
    var parent=Path.GetDirectoryName(p); if(parent==p)break; p=parent;
   }
  }
  public static string Kind(string path) {
   string e=Path.GetExtension(path).ToLowerInvariant();
   if(new[]{".mp4",".mov",".mkv",".avi",".webm",".mxf",".mts"}.Contains(e))return "Видео";
   if(new[]{".mp3",".wav",".weba",".flac",".aac",".m4a",".opus",".ogg"}.Contains(e))return "Аудио";
   if(new[]{".png",".jpg",".jpeg",".webp",".svg",".psd",".tif",".exr"}.Contains(e))return "Графика";
   if(new[]{".mlt",".kdenlive",".osp",".prproj",".aep",".aepx",".aet",".veg",".drp",".dra",".fcpxml",".psdeps",".vproj",".capcut",".vcp"}.Contains(e))return "Проект";
   return "Другое";
  }
  static Item Describe(string source,string relative,bool linked) {
   NoLinks(source); var f=new FileInfo(source);
   return new Item{Source=f.FullName,Relative=relative,Size=f.Length,Stamp=f.LastWriteTimeUtc.Ticks,Category=Kind(source),Linked=linked};
  }
  static void Walk(Scan scan,string dir,CancellationToken token,Action<ProgressInfo> progress) {
   token.ThrowIfCancellationRequested();
   try {
    foreach(string file in Directory.GetFiles(dir)) {
     token.ThrowIfCancellationRequested();
     try {scan.Files.Add(Describe(file,file.Substring(scan.Root.Length+1),false));}
     catch(Exception ex){scan.Findings.Add(new Finding("Ошибка",file,ex.Message));}
    }
    if(progress!=null)progress(new ProgressInfo(0,0,"Найдено файлов: "+scan.Files.Count));
    foreach(string sub in Directory.GetDirectories(dir)) {
     token.ThrowIfCancellationRequested();
     if((File.GetAttributes(sub)&FileAttributes.ReparsePoint)!=0)scan.Findings.Add(new Finding("Ошибка",sub,"Папка-ссылка. Выбери её настоящее расположение отдельно."));
     else {scan.Directories.Add(sub.Substring(scan.Root.Length+1));Walk(scan,sub,token,progress);}
    }
   } catch(OperationCanceledException){throw;}
   catch(Exception ex){scan.Findings.Add(new Finding("Ошибка",dir,ex.Message));}
  }
  public static Scan Inspect(string root,CancellationToken token,Action<ProgressInfo> progress) {
   root=Normalize(root);
   if(!Directory.Exists(root))throw new IOException("Папка проекта не найдена.");
   if(Normalize(Path.GetPathRoot(root))==root)throw new IOException("Выбери папку проекта, а не весь диск.");
   NoLinks(root);
   var scan=new Scan{Root=root}; Walk(scan,root,token,progress);
     foreach(Item project in scan.Files.Where(x=>x.Category=="Проект"||Path.GetExtension(x.Source).Equals(".xml",StringComparison.OrdinalIgnoreCase)).ToArray()) {
    if(Path.GetExtension(project.Source).Equals(".xml",StringComparison.OrdinalIgnoreCase)) {
     if(!IsInterchangeXml(project.Source))continue;
     project.Category="Проект";
    }
    token.ThrowIfCancellationRequested(); scan.Projects++;
    string ext=Path.GetExtension(project.Source).ToLowerInvariant();
    if(ext==".mlt"||ext==".kdenlive")InspectMlt(scan,project,token);
    else if(ext==".osp")InspectOsp(scan,project,token);
    else if(new[]{".prproj",".aepx",".fcpxml",".xml",".psdeps"}.Contains(ext))InspectPopular(scan,project,token);
    else if(new[]{".aep",".aet"}.Contains(ext))scan.Findings.Add(new Finding("Проверить",project.Relative,"After Effects: двоичный проект сохраняется без изменений. Для сбора связей запусти Adobe/Export-AfterEffects-Dependencies.jsx в After Effects и положи выгрузку .psdeps в эту папку, затем проверь снова. Либо используй Collect Files в редакторе."));
    else if(new[]{".drp",".dra"}.Contains(ext))scan.Findings.Add(new Finding("Проверить",project.Relative,"DaVinci Resolve: оригинал сохранится, но связи DRP не разобраны. Экспортируй FCPXML/XML для проверки доступных ссылок или собери Project Archive с медиа в самом Resolve. XML не заменяет исходный монтаж Resolve."));
    else scan.Findings.Add(new Finding("Формат",project.Relative,"Файл сохранится. Автоматическая проверка связей этого формата пока не поддерживается."));
   }
   if(scan.Projects==0)scan.Findings.Add(new Finding("Информация","Папка","Будет сохранена папка целиком. Файлы проекта редактора не обнаружены."));
   return scan;
  }
  static string Property(XmlNode node,string name) {
   var p=node.SelectSingleNode("property[@name='"+name+"']");
   if(p==null)return "";var a=p.Attributes["value"];return a==null?p.InnerText:a.Value;
  }
  static readonly string ResourceQuery="//property[@name='resource' or @name='warp_resource' or @name='shotcut:proxy' or @name='shotcut:originalResource' or @name='shotcut:detail' or @name='kdenlive:proxy' or @name='kdenlive:originalurl']";
  static XmlDocument ReadMlt(string file) {
   if(new FileInfo(file).Length>20*1024*1024)throw new IOException("Слишком большой XML: связи не проверены.");
   var doc=new XmlDocument{XmlResolver=null,PreserveWhitespace=true};
   var settings=new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=20*1024*1024};
   using(var reader=XmlReader.Create(file,settings))doc.Load(reader);
   if(doc.DocumentElement==null||doc.DocumentElement.Name!="mlt")throw new IOException("Не распознан корневой элемент MLT.");
   return doc;
  }
  static string Value(XmlNode node){return node.Attributes["value"]==null?node.InnerText:node.Attributes["value"].Value;}
  static void SetValue(XmlNode node,string text){if(node.Attributes["value"]==null)node.InnerText=text;else node.Attributes["value"].Value=text;}
  static void Manual(Scan scan,MltPlan plan,string message) {plan.CanRewrite=false;scan.Findings.Add(new Finding("Проверить",plan.Relative,message));}
  static void InspectMlt(Scan scan,Item project,CancellationToken token) {
   var plan=new MltPlan{Source=project.Source,Relative=project.Relative,Editor=Path.GetExtension(project.Source).Equals(".kdenlive",StringComparison.OrdinalIgnoreCase)?"Kdenlive":"Shotcut"};scan.MltPlans.Add(plan);
   if(project.Size>20*1024*1024){plan.CanRewrite=false;scan.Findings.Add(new Finding("Формат",project.Relative,"Слишком большой XML: связи не проверены."));return;}
   try {
    var doc=ReadMlt(project.Source);
    if(plan.Editor=="Kdenlive"){
     var version=doc.SelectSingleNode("//property[@name='kdenlive:docproperties.version']");
     if(version==null||version.InnerText!="1.1")Manual(scan,plan,"Версия документа Kdenlive пока не проверена. Сохранится оригинал без автоматической перепривязки.");
     foreach(XmlNode title in doc.SelectNodes("//property[@name='xmldata']"))if(title.InnerText.Contains("QGraphicsPixmapItem")||title.InnerText.Contains("url=\""))Manual(scan,plan,"Титр содержит внешний графический ресурс; требуется ручная проверка.");
     if(doc.SelectNodes("//property[@name='kdenlive:docproperties.subtitlefiles']").Cast<XmlNode>().Any(x=>!String.IsNullOrWhiteSpace(Value(x))))Manual(scan,plan,"Внешние субтитры Kdenlive требуют отдельной проверки.");
    }
    var baseDir=Path.GetDirectoryName(project.Source);
    var rootAttr=doc.DocumentElement.GetAttribute("root");
    if(!String.IsNullOrWhiteSpace(rootAttr))baseDir=Path.GetFullPath(Path.IsPathRooted(rootAttr)?rootAttr:Path.Combine(baseDir,rootAttr));
    var nodes=doc.SelectNodes(ResourceQuery);
    var binIds=new HashSet<string>(doc.SelectNodes("//playlist[@id='main_bin']/entry[@producer]").Cast<XmlNode>().Select(x=>x.Attributes["producer"].Value),StringComparer.Ordinal);
    var bySource=scan.Files.ToDictionary(x=>x.Source,StringComparer.OrdinalIgnoreCase);
    for(int index=0;index<nodes.Count;index++) {
     XmlNode node=nodes[index];
     token.ThrowIfCancellationRequested();
     string service=Property(node.ParentNode,"mlt_service");
     string name=node.Attributes["name"].Value;
     string value=Value(node),prefix="";
     if(String.IsNullOrWhiteSpace(value)||value=="-"||value=="0"||value.StartsWith("#")||value.StartsWith("<"))continue;
     if(new[]{"color","colour","noise","tone","qtext","pango","count"}.Contains(service))continue;
     // shotcut:detail is display metadata and may contain ordinary labels.
     bool detail=name=="shotcut:detail";
     if(service=="timewarp" && name=="resource") {
      var match=Regex.Match(value,@"^[+-]?(?:\d+(?:[.,]\d*)?|\.\d+):");
      if(!match.Success){Manual(scan,plan,"Не распознан путь клипа с изменённой скоростью. Отдельная MLT-копия не создаётся.");continue;}
      prefix=match.Value;value=value.Substring(prefix.Length);
     }
     Uri uri;
     if(Uri.TryCreate(value,UriKind.Absolute,out uri) && !uri.IsFile && !Path.IsPathRooted(value)) {
      if(!detail)Manual(scan,plan,"Внешний адрес не загружается: "+value);continue;
     }
     string local=(uri!=null&&uri.IsFile)?uri.LocalPath:value;
     if(local.StartsWith("\\\\",StringComparison.Ordinal)||local.StartsWith("//",StringComparison.Ordinal)) {if(!detail)Manual(scan,plan,"Сетевой ресурс не открывается автоматически: "+value);continue;}
     if(local.IndexOfAny(new[]{'?','*'})>=0 || Regex.IsMatch(local,@"%0?\d*d")) {if(!detail)Manual(scan,plan,"Последовательность изображений требует ручной проверки: "+value);continue;}
     string path=Path.GetFullPath(Path.IsPathRooted(local)?local:Path.Combine(baseDir,local));
     NoLinks(path);
     if(!File.Exists(path)){if(!detail){plan.CanRewrite=false;scan.Findings.Add(new Finding("Не найден",project.Relative,path));}continue;}
     if(plan.Editor=="Kdenlive"&&name=="resource"&&node.ParentNode.Attributes["id"]!=null&&binIds.Contains(node.ParentNode.Attributes["id"].Value)){
      string proxy=Property(node.ParentNode,"kdenlive:proxy");long expected;
      if((String.IsNullOrWhiteSpace(proxy)||proxy=="-")&&Int64.TryParse(Property(node.ParentNode,"kdenlive:file_size"),out expected)&&expected>0&&new FileInfo(path).Length!=expected)
       Manual(scan,plan,"Размер исходника отличается от сохранённых сведений Kdenlive. Обнови клип и сохрани проект в редакторе перед переносом: "+Path.GetFileName(path));
     }
     if(!bySource.ContainsKey(path)) {
      string pathId;
      using(var h=SHA256.Create())pathId=BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(path.ToUpperInvariant()))).Replace("-","").Substring(0,16);
      var linked=Describe(path,Path.Combine("_linked",pathId,Path.GetFileName(path)),true);scan.Files.Add(linked);bySource.Add(path,linked);
      scan.Findings.Add(new Finding("Внешний файл",project.Relative,path+" — будет добавлен в _linked."));
     }
     plan.References.Add(new MltReference{Index=index,Source=path,Prefix=prefix});
     if(!detail&&(service.StartsWith("xml")||new[]{".mlt",".xml",".kdenlive"}.Contains(Path.GetExtension(path).ToLowerInvariant())))Manual(scan,plan,"Вложенный проект требует отдельной проверки. Отдельная MLT-копия не создаётся.");
    }
    if(doc.SelectNodes("//*[@resource or @warp_resource or @filename]").Count>0)Manual(scan,plan,"Найдены пути в XML-атрибутах: автоматическая перепривязка этого варианта пока не поддерживается.");
    if(doc.SelectNodes("//property[@name='filename' or @name='av.file' or @name='luma' or @name='lut']").Count>0)Manual(scan,plan,"Найдены дополнительные параметры файлов или эффектов. Для этого проекта требуется ручная проверка путей.");
    if(plan.CanRewrite)scan.Findings.Add(new Finding("MLT-копия",project.Relative,"Будет создан отдельный проект с относительными ссылками на собранные файлы. Исходный проект сохранится без изменений."));
    scan.Findings.Add(new Finding("Проверить",project.Relative,"Шрифты, плагины и ресурсы эффектов нужно проверить в редакторе. Автоматически проверяются основные пути MLT."));
   } catch(OperationCanceledException){throw;}
   catch(Exception ex){plan.CanRewrite=false;scan.Findings.Add(new Finding("Формат",project.Relative,"Связи MLT не проверены: "+ex.Message));}
  }
  static string RelativeFile(string fromDirectory,string file) {
   var from=new Uri(Path.GetFullPath(fromDirectory).TrimEnd('\\')+"\\");
   return Uri.UnescapeDataString(from.MakeRelativeUri(new Uri(Path.GetFullPath(file))).ToString());
  }
  static void CreateDerived(Scan scan,string bundle,Manifest manifest,CancellationToken token) {
   var originals=scan.Files.ToDictionary(x=>x.Source,StringComparer.OrdinalIgnoreCase);
   foreach(var plan in scan.MltPlans.Where(x=>x.CanRewrite)) {
    token.ThrowIfCancellationRequested();
    string copied=SafeChild(Path.Combine(bundle,"Project"),plan.Relative);
    var doc=ReadMlt(copied);
    var nodes=doc.SelectNodes(ResourceQuery);
    string target=SafeChild(Path.Combine(bundle,"Ready"),plan.Relative);
    foreach(var reference in plan.References) {
     if(reference.Index<0||reference.Index>=nodes.Count)throw new IOException("Изменился состав ссылок MLT.");
     Item item=originals[reference.Source];
     string asset=SafeChild(Path.Combine(bundle,"Project"),item.Relative);
     SetValue(nodes[reference.Index],reference.Prefix+RelativeFile(Path.GetDirectoryName(target),asset));
    }
    // MLT defaults to the document's own directory when root is absent.
    doc.DocumentElement.RemoveAttribute("root");
    if(plan.Editor=="Kdenlive"){
     foreach(XmlNode p in doc.SelectNodes("//property[@name='kdenlive:docproperties.storagefolder' or @name='kdenlive:docproperties.projectfolder']"))SetValue(p,"");
    }
    Directory.CreateDirectory(Path.GetDirectoryName(target));
    var settings=new XmlWriterSettings{Encoding=new UTF8Encoding(false),Indent=false,CheckCharacters=true};
    using(var output=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None))
    using(var writer=XmlWriter.Create(output,settings))doc.Save(writer);
    string relative="Ready/"+plan.Relative.Replace('\\','/');
    manifest.Files.Add(new SavedItem{Path=relative,Size=new FileInfo(target).Length,SHA256=Hash(target,token),Original=plan.Source,Derived=true});
    manifest.DerivedProjects.Add(new DerivedProject{Original="Project/"+plan.Relative.Replace('\\','/'),Path=relative,Editor=plan.Editor,RewrittenReferences=plan.References.Count});
   }
  }
  public static string SafeChild(string root,string relative) {
   if(String.IsNullOrWhiteSpace(relative)||Path.IsPathRooted(relative)||relative.Contains(":"))throw new IOException("Недопустимый путь в списке файлов.");
   string result=Path.GetFullPath(Path.Combine(root,relative));
   if(!Inside(result,root))throw new IOException("Путь выходит за пределы копии.");
   return result;
  }
  public static string Pack(Scan scan,string parent,CancellationToken token,Action<ProgressInfo> progress) {
   if(scan.Blocked)throw new IOException("Сначала исправь ошибки чтения папки и выполни проверку заново.");
   if(scan.Files.Count==0)throw new IOException("В папке нет файлов.");
   parent=Normalize(parent);
   if(parent.Equals(scan.Root,StringComparison.OrdinalIgnoreCase)||Inside(parent,scan.Root))throw new IOException("Место сохранения должно находиться вне папки проекта.");
   NoLinks(parent);
   foreach(var f in scan.Files)if(Inside(f.Source,parent)||f.Source.Equals(parent,StringComparison.OrdinalIgnoreCase))throw new IOException("Место сохранения содержит исходники. Выбери другую папку.");
   Directory.CreateDirectory(parent);
   var drive=new DriveInfo(Path.GetPathRoot(parent));
   long derivedBytes=scan.Files.Where(x=>x.Category=="Проект").Sum(x=>x.Size)*2;
   if(drive.AvailableFreeSpace<scan.Bytes+derivedBytes+16*1024*1024)throw new IOException("Недостаточно свободного места для копии.");
   string stamp=DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
   string bundle=Path.Combine(parent,Path.GetFileName(scan.Root)+"_"+stamp+"_"+Guid.NewGuid().ToString("N").Substring(0,6));
   Directory.CreateDirectory(bundle);
   var manifest=new Manifest{Source=scan.Root,CreatedUtc=DateTime.UtcNow.ToString("o"),Status="INCOMPLETE",Findings=scan.Findings,Directories=scan.Directories.Select(x=>"Project/"+x.Replace('\\','/')).ToList()};
   string marker=Path.Combine(bundle,"НЕ ЗАВЕРШЕНО.txt");
   File.WriteAllText(marker,"Копия не завершена. Только статус COMPLETE в manifest.json означает успешную проверку всех скопированных файлов.",Encoding.UTF8);
   long done=0;
   try {
    foreach(string dir in scan.Directories)Directory.CreateDirectory(SafeChild(Path.Combine(bundle,"Project"),dir));
    foreach(var item in scan.Files) {
     token.ThrowIfCancellationRequested(); NoLinks(item.Source);
     var fi=new FileInfo(item.Source);
     if(!fi.Exists||fi.Length!=item.Size||fi.LastWriteTimeUtc.Ticks!=item.Stamp)throw new IOException("Исходник изменился после проверки: "+item.Relative+". Выполни проверку заново.");
     string target=SafeChild(Path.Combine(bundle,"Project"),item.Relative);
     Directory.CreateDirectory(Path.GetDirectoryName(target));
     byte[] buffer=new byte[1024*1024]; string hash;
     using(var input=new FileStream(item.Source,FileMode.Open,FileAccess.Read,FileShare.Read))
     using(var output=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None))
     using(var sha=SHA256.Create()) {
      int read;long count=0;
      while((read=input.Read(buffer,0,buffer.Length))>0) {
       token.ThrowIfCancellationRequested();output.Write(buffer,0,read);sha.TransformBlock(buffer,0,read,buffer,0);count+=read;done+=read;
       if(progress!=null)progress(new ProgressInfo(done,scan.Bytes,"Копирование · "+item.Relative));
      }
      sha.TransformFinalBlock(new byte[0],0,0);
      if(count!=item.Size||File.GetLastWriteTimeUtc(item.Source).Ticks!=item.Stamp)throw new IOException("Исходник изменился при копировании: "+item.Relative);
      hash=BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
     }
     token.ThrowIfCancellationRequested();
     if(progress!=null)progress(new ProgressInfo(done,scan.Bytes,"Проверка содержимого · "+item.Relative));
     if(Hash(target,token)!=hash)throw new IOException("Не совпало содержимое копии: "+item.Relative);
     File.SetLastWriteTimeUtc(target,new DateTime(item.Stamp,DateTimeKind.Utc));
     manifest.Files.Add(new SavedItem{Path="Project/"+item.Relative.Replace('\\','/'),Size=item.Size,SHA256=hash,Original=item.Source});
    }
    var after=new Scan{Root=scan.Root};Walk(after,scan.Root,token,null);
    var original=scan.Files.Where(x=>!x.Linked).ToDictionary(x=>x.Source,StringComparer.OrdinalIgnoreCase);
    if(after.Blocked||after.Files.Count!=original.Count||after.Files.Any(x=>!original.ContainsKey(x.Source)||original[x.Source].Size!=x.Size||original[x.Source].Stamp!=x.Stamp)||!after.Directories.OrderBy(x=>x).SequenceEqual(scan.Directories.OrderBy(x=>x)))
     throw new IOException("Состав папки изменился во время сохранения. Закрой редактор и проверь папку заново.");
    foreach(var f in scan.Files.Where(x=>x.Linked)) {NoLinks(f.Source);var info=new FileInfo(f.Source);if(!info.Exists||info.Length!=f.Size||info.LastWriteTimeUtc.Ticks!=f.Stamp)throw new IOException("Внешний исходник изменился: "+f.Source);}
    CreateDerived(scan,bundle,manifest,token);
    CreateOspDerived(scan,bundle,manifest,token);
    token.ThrowIfCancellationRequested();manifest.Status="COMPLETE";
    File.WriteAllText(Path.Combine(bundle,"manifest.json"),Json().Serialize(manifest),Encoding.UTF8);
    File.WriteAllText(marker,"ЗАВЕРШЕНО. Статус COMPLETE записан в manifest.json; этот файл оставлен как журнал начала операции.",Encoding.UTF8);
    File.Move(marker,Path.Combine(bundle,"Журнал операции.txt"));
    var report=new StringBuilder("СЕЙФ ПРОЕКТА 0.4\r\n\r\nКопирование и проверка SHA-256 завершены.\r\nФайлов: "+manifest.Files.Count+"\r\nПроектов с обновлёнными ссылками: "+manifest.DerivedProjects.Count+"\r\n\r\nProject — точные копии исходных файлов. Ready — отдельные проекты Shotcut, Kdenlive и OpenShot с основными ссылками на собранные файлы в Project. Переноси всю папку сейфа целиком, затем открывай проект из Ready.\r\nЕсли отдельной копии проекта нет, проверь замечания ниже. Premiere Pro, After Effects и обменные XML: собираются известные ссылки без изменения проекта. После переноса нужна ручная перепривязка; полного покрытия и проверки в этих редакторах пока нет.\r\nШрифты, плагины и все варианты ресурсов эффектов автоматически не собираются. Открытие в редакторе на другом ПК нужно проверить.\r\n\r\nЗАМЕЧАНИЯ\r\n");
    foreach(var f in scan.Findings)report.AppendLine(f.Level+" | "+f.File+" | "+f.Message);
    File.WriteAllText(Path.Combine(bundle,"Прочитай меня.txt"),report.ToString(),Encoding.UTF8);
    var map=new StringBuilder("Исходный путь\tПуть в сейфе\tSHA256\r\n");
    foreach(var entry in manifest.Files.Where(x=>!x.Derived))map.AppendLine(entry.Original.Replace("\t"," ").Replace("\r"," ").Replace("\n"," ")+"\t"+entry.Path+"\t"+entry.SHA256);
    File.WriteAllText(Path.Combine(bundle,"Карта исходников.tsv"),map.ToString(),Encoding.UTF8);
    return bundle;
   } catch(Exception ex) {
    manifest.Status=ex is OperationCanceledException?"CANCELLED":"FAILED";
    try {File.WriteAllText(Path.Combine(bundle,"manifest.json"),Json().Serialize(manifest),Encoding.UTF8);File.AppendAllText(marker,"\r\n"+ex.Message,Encoding.UTF8);}catch{}
    throw new IOException((ex is OperationCanceledException?"Операция отменена.":ex.Message)+"\r\nНезавершённая копия сохранена: "+bundle,ex);
   }
  }
  public static int Verify(string bundle,CancellationToken token,Action<ProgressInfo> progress) {
   bundle=Normalize(bundle);NoLinks(bundle);
   string path=Path.Combine(bundle,"manifest.json");
   if(!File.Exists(path)||new FileInfo(path).Length>64*1024*1024)throw new IOException("В этой папке не найден допустимый manifest.json Сейфа проекта.");
   var manifest=Json().Deserialize<Manifest>(File.ReadAllText(path));
   if(manifest==null||manifest.Format!="ProjectSafe/1"||manifest.Status!="COMPLETE"||manifest.Files==null||manifest.Files.Count==0)throw new IOException("Эта копия не завершена или её формат не поддерживается.");
   if(manifest.Directories!=null)foreach(string dir in manifest.Directories){string local=SafeChild(bundle,dir);NoLinks(local);if(!Directory.Exists(local))throw new IOException("Папка отсутствует: "+dir);}
   var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);int count=0;
   foreach(var f in manifest.Files) {
    token.ThrowIfCancellationRequested();string file=SafeChild(bundle,f.Path);NoLinks(file);
    if(!names.Add(file))throw new IOException("Повторяющийся путь в списке файлов.");
    if(progress!=null)progress(new ProgressInfo(count,manifest.Files.Count,"Проверка · "+f.Path));
    if(!File.Exists(file)||new FileInfo(file).Length!=f.Size||!String.Equals(Hash(file,token),f.SHA256,StringComparison.OrdinalIgnoreCase))throw new IOException("Файл отсутствует или изменён: "+f.Path);
    count++;
   }
   return count;
  }
 }
}
