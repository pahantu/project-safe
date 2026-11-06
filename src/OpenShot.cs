using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Xml;
using System.Threading;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace ProjectSafe {
 public class OspReference {
  public List<string> Tokens=new List<string>();
  public string Source;
 }
 public class OspPlan {
  public string Source,Relative;
  public bool CanRewrite=true;
  public List<OspReference> References=new List<OspReference>();
 }
 public static partial class Vault {
  static readonly HashSet<string> OspPathKeys=new HashSet<string>(new[]{"path","image","resource","protobuf_data_path","lut_path"},StringComparer.Ordinal);
  static Dictionary<string,object> ReadOsp(string file) {
   if(new FileInfo(file).Length>48*1024*1024)throw new IOException("Слишком большой проект OpenShot.");
   var obj=Json().DeserializeObject(File.ReadAllText(file)) as Dictionary<string,object>;
   if(obj==null||!obj.ContainsKey("clips")||!obj.ContainsKey("files")||!obj.ContainsKey("layers")||!obj.ContainsKey("version"))throw new IOException("Не распознана структура проекта OpenShot.");
   return obj;
  }
  static void OspManual(Scan scan,OspPlan plan,string message) {plan.CanRewrite=false;if(!scan.Findings.Any(x=>x.File==plan.Relative&&x.Message==message))scan.Findings.Add(new Finding("Проверить",plan.Relative,message));}
  static string AssetDirectory(string file) {
   string stem=Path.GetFileNameWithoutExtension(file);if(stem.Length>248)stem=stem.Substring(0,248);
   string path=Path.Combine(Path.GetDirectoryName(file),stem+"_assets");
   string legacy=Path.Combine(Path.GetDirectoryName(file),stem.Substring(0,Math.Min(30,stem.Length))+"_assets");
   return !Directory.Exists(path)&&Directory.Exists(legacy)?legacy:path;
  }
  static void InspectOsp(Scan scan,Item project,CancellationToken token) {
   var plan=new OspPlan{Source=project.Source,Relative=project.Relative};scan.OspPlans.Add(plan);
   try {
    var data=ReadOsp(project.Source);
    var version=data["version"] as Dictionary<string,object>;
    string editor=version!=null&&version.ContainsKey("openshot-qt")?Convert.ToString(version["openshot-qt"]):"";
    if(!editor.StartsWith("4.1.",StringComparison.Ordinal))OspManual(scan,plan,"Эта версия OpenShot пока не проверена: "+editor+". Оригинал будет сохранён.");
    if(data.ContainsKey("auto_optimize")&&data["auto_optimize"]!=null)OspManual(scan,plan,"OpenShot Auto Optimize требует отдельной проверки. Оригинал будет сохранён.");
    var bySource=scan.Files.ToDictionary(x=>x.Source,StringComparer.OrdinalIgnoreCase);
    WalkOsp(data,new List<string>(),(tokens,key,value)=>{
     token.ThrowIfCancellationRequested();
     if(String.IsNullOrWhiteSpace(value))return;
     string normalizedValue=value.Replace('\\','/');
     bool optional=key=="image"&&((tokens.Count>0&&tokens[0]=="files")||normalizedValue.Contains("/thumbnail/")||normalizedValue.StartsWith("thumbnail/",StringComparison.Ordinal));
     string local=value;
     if(value.StartsWith("@transitions/")||value.StartsWith("@colors/")||value.StartsWith("@emojis/")) {
      string message="Встроенные ресурсы OpenShot требуют установленного редактора той же версии.";
      if(!scan.Findings.Any(x=>x.File==plan.Relative&&x.Message==message))scan.Findings.Add(new Finding("Информация",plan.Relative,message));return;
     }
     if(value.StartsWith("@assets/",StringComparison.Ordinal))local=SafeChild(AssetDirectory(project.Source),value.Substring(8));
     else if(value.StartsWith("@",StringComparison.Ordinal)){OspManual(scan,plan,"Не распознан служебный путь OpenShot: "+value);return;}
     Uri uri;
     if(Uri.TryCreate(local,UriKind.Absolute,out uri)&&!uri.IsFile&&!Path.IsPathRooted(local)){if(!optional)OspManual(scan,plan,"Внешний адрес не собирается: "+value);return;}
     if(uri!=null&&uri.IsFile)local=uri.LocalPath;
     if(local.StartsWith("\\\\",StringComparison.Ordinal)||local.StartsWith("//",StringComparison.Ordinal)){OspManual(scan,plan,"Сетевой ресурс не открывается: "+value);return;}
     if(local.IndexOfAny(new[]{'*','?'})>=0){OspManual(scan,plan,"Специальный путь или последовательность: "+value);return;}
     string path=Path.GetFullPath(Path.IsPathRooted(local)?local:Path.Combine(Path.GetDirectoryName(project.Source),local));
     NoLinks(path);
     if(!File.Exists(path)) {
      if(optional){plan.References.Add(new OspReference{Tokens=new List<string>(tokens),Source=null});return;}
      plan.CanRewrite=false;if(!scan.Findings.Any(x=>x.Level=="Не найден"&&x.File==plan.Relative&&x.Message==path))scan.Findings.Add(new Finding("Не найден",plan.Relative,path));return;
     }
     if(!bySource.ContainsKey(path)) {
      string id;using(var sha=SHA256.Create())id=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(path.ToUpperInvariant()))).Replace("-","").Substring(0,16);
      var item=Describe(path,Path.Combine("_linked",id,Path.GetFileName(path)),true);scan.Files.Add(item);bySource.Add(path,item);
      scan.Findings.Add(new Finding("Внешний файл",plan.Relative,path+" — будет добавлен в _linked."));
     }
     plan.References.Add(new OspReference{Tokens=new List<string>(tokens),Source=path});
     string ext=Path.GetExtension(path).ToLowerInvariant();
     if(new[]{".osp",".blend",".mlt",".kdenlive"}.Contains(ext))OspManual(scan,plan,"Вложенный проект или 3D-сцена требует ручной проверки: "+Path.GetFileName(path));
     if(ext==".svg") {
      var svg=new XmlDocument{XmlResolver=null};
      using(var reader=XmlReader.Create(path,new XmlReaderSettings{XmlResolver=null,DtdProcessing=DtdProcessing.Prohibit,MaxCharactersInDocument=5*1024*1024}))svg.Load(reader);
      if(svg.SelectNodes("//*[local-name()='image']").Count>0||svg.OuterXml.Contains("url("))OspManual(scan,plan,"SVG содержит дополнительные внешние ресурсы: "+Path.GetFileName(path));
     }
    });
    if(plan.CanRewrite)scan.Findings.Add(new Finding("OSP-копия",plan.Relative,"Будет создан отдельный проект OpenShot с относительными ссылками; монтаж и ключевые кадры сохранятся."));
    scan.Findings.Add(new Finding("Проверить",plan.Relative,"Шрифты и внешние дополнения нужно проверить на другом компьютере."));
   } catch(OperationCanceledException){throw;}
   catch(Exception ex){plan.CanRewrite=false;scan.Findings.Add(new Finding("Формат",plan.Relative,"Связи OpenShot не проверены: "+ex.Message));}
  }
  static void WalkOsp(object value,List<string> tokens,Action<List<string>,string,string> visit) {
   var dict=value as Dictionary<string,object>;
   if(dict!=null) {
    foreach(var pair in dict){var next=new List<string>(tokens);next.Add(pair.Key);if(OspPathKeys.Contains(pair.Key)&&pair.Value is string)visit(next,pair.Key,(string)pair.Value);else WalkOsp(pair.Value,next,visit);}
   }else{
    var list=value as IList;if(list==null)return;
    for(int i=0;i<list.Count;i++){var next=new List<string>(tokens);next.Add(i.ToString(System.Globalization.CultureInfo.InvariantCulture));WalkOsp(list[i],next,visit);}
   }
  }
  static void SetOsp(object data,List<string> tokens,string value) {
   object current=data;
   for(int i=0;i<tokens.Count-1;i++){var dict=current as Dictionary<string,object>;current=dict!=null?dict[tokens[i]]:((IList)current)[Int32.Parse(tokens[i],System.Globalization.CultureInfo.InvariantCulture)];}
   var parent=current as Dictionary<string,object>;if(parent==null)throw new IOException("Изменился состав ссылок OpenShot.");parent[tokens.Last()]=value;
  }
  static void CreateOspDerived(Scan scan,string bundle,Manifest manifest,CancellationToken token) {
   var originals=scan.Files.ToDictionary(x=>x.Source,StringComparer.OrdinalIgnoreCase);
   foreach(var plan in scan.OspPlans.Where(x=>x.CanRewrite)) {
    token.ThrowIfCancellationRequested();var data=ReadOsp(SafeChild(Path.Combine(bundle,"Project"),plan.Relative));
    string target=SafeChild(Path.Combine(bundle,"Ready"),plan.Relative);
    foreach(var reference in plan.References){string path=reference.Source==null?"":RelativeFile(Path.GetDirectoryName(target),SafeChild(Path.Combine(bundle,"Project"),originals[reference.Source].Relative));SetOsp(data,reference.Tokens,path);}
    Directory.CreateDirectory(Path.GetDirectoryName(target));
    using(var stream=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None))using(var writer=new StreamWriter(stream,new UTF8Encoding(false)))writer.Write(Json().Serialize(data));
    string relative="Ready/"+plan.Relative.Replace('\\','/');
    manifest.Files.Add(new SavedItem{Path=relative,Size=new FileInfo(target).Length,SHA256=Hash(target,token),Original=plan.Source,Derived=true});
    manifest.DerivedProjects.Add(new DerivedProject{Original="Project/"+plan.Relative.Replace('\\','/'),Path=relative,Editor="OpenShot",RewrittenReferences=plan.References.Count});
   }
  }
 }
}
